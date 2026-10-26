"""Leitura dos valores de um XLSX usando somente ZIP e XML da biblioteca padrão.

Não executa fórmulas, não acessa relacionamentos externos e não extrai arquivos.
As dimensões declaradas pela planilha não limitam os dados percorridos.
"""

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
import posixpath
import re
from urllib.parse import unquote, urlsplit
from xml.etree import ElementTree as ET
from zipfile import BadZipFile, ZipFile


INVALID_XLSX_MESSAGE = "arquivo corrompido ou não é um XLSX válido; abra e salve novamente como .xlsx"


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _target(base: str, target: str) -> str:
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or "\\" in target:
        raise ValueError("relacionamento externo ou caminho inválido no XLSX")
    path = unquote(parsed.path)
    if path.startswith("/"):
        path = path.lstrip("/")
    else:
        path = posixpath.join(posixpath.dirname(base), path)
    path = posixpath.normpath(path)
    if path in ("", ".", "..") or path.startswith("../") or "\x00" in path:
        raise ValueError("relacionamento fora do pacote XLSX")
    return path


def _string(element: ET.Element) -> str:
    """Concatena rich text, sem acrescentar guias fonéticos ao valor da célula."""
    pieces = []

    def collect(node):
        if _local(node.tag) in ("rPh", "phoneticPr"):
            return
        if _local(node.tag) == "t":
            pieces.append(node.text or "")
        else:
            for child in node:
                collect(child)

    collect(element)
    # Uma passagem preserva escapes literais como _x005F_x0041_.
    return re.sub(r"_x([0-9a-fA-F]{4})_", lambda match: chr(int(match[1], 16)), "".join(pieces))


@dataclass(frozen=True)
class Cell:
    value: object = None
    data_type: str = "n"


EMPTY_CELL = Cell()


def _column(reference: str) -> tuple[int, int]:
    matched = re.fullmatch(r"([A-Za-z]+)([1-9][0-9]*)", reference)
    if not matched:
        raise ValueError("referência de célula inválida no XLSX")
    column = 0
    for letter in matched[1].upper():
        column = column * 26 + ord(letter) - ord("A") + 1
    row = int(matched[2])
    if column > 16384 or row > 1048576:
        raise ValueError("referência de célula fora dos limites do XLSX")
    return column, row


class Worksheet:
    def __init__(self, workbook, title: str, path: str):
        self.title = title
        self._workbook = workbook
        self._path = path
        self._rows = None

    def _cell(self, element: ET.Element) -> Cell:
        children = {_local(child.tag): child for child in element}
        if "f" in children:
            return Cell("=" + (children["f"].text or ""), "f")
        value = children.get("v")
        text = value.text if value is not None else None
        kind = element.get("t", "n")
        if kind == "inlineStr":
            inline = children.get("is")
            return Cell(_string(inline) if inline is not None else "", "s")
        if kind == "s":
            try:
                index = int(text)
                if index < 0:
                    raise ValueError
                return Cell(self._workbook.shared_strings[index], "s")
            except (TypeError, ValueError, IndexError) as exc:
                raise ValueError("índice de texto compartilhado inválido no XLSX") from exc
        if text is None:
            return EMPTY_CELL
        if kind in ("str", "e"):
            return Cell(text, kind)
        if kind == "b":
            if text not in ("0", "1"):
                raise ValueError("valor booleano inválido no XLSX")
            return Cell(text == "1", kind)
        if kind == "d":
            try:
                return Cell(datetime.fromisoformat(text.replace("Z", "+00:00")), kind)
            except ValueError as exc:
                raise ValueError("data inválida no XLSX") from exc
        if kind != "n":
            raise ValueError(f"tipo de célula XLSX não suportado: {kind!r}")
        try:
            return Cell(Decimal(text), "n")
        except InvalidOperation as exc:
            raise ValueError("valor numérico inválido no XLSX") from exc

    def _read_rows(self):
        rows = {}
        previous_row = 0
        with self._workbook.archive.open(self._path) as source:
            for _, element in ET.iterparse(source, events=("end",)):
                if _local(element.tag) != "row":
                    continue
                try:
                    number = int(element.get("r", previous_row + 1))
                except ValueError as exc:
                    raise ValueError("número de linha inválido no XLSX") from exc
                if not previous_row < number <= 1048576:
                    raise ValueError("linhas fora de ordem ou repetidas no XLSX")
                previous_row = number
                cells = {}
                previous_column = 0
                for node in element:
                    if _local(node.tag) != "c":
                        continue
                    if node.get("r"):
                        column, reference_row = _column(node.get("r"))
                        if reference_row != number:
                            raise ValueError("célula aponta para outra linha no XLSX")
                    else:
                        column = previous_column + 1
                    if column in cells or column > 16384:
                        raise ValueError("coluna repetida ou inválida no XLSX")
                    previous_column = column
                    cells[column] = self._cell(node)
                width = max(cells, default=0)
                rows[number] = tuple(cells.get(column, EMPTY_CELL) for column in range(1, width + 1))
                element.clear()
        self._rows = rows

    def iter_rows(self, min_row=1, max_row=None, values_only=False):
        if self._rows is None:
            self._read_rows()
        last_row = max(self._rows, default=0) if max_row is None else max_row
        for number in range(min_row, last_row + 1):
            row = self._rows.get(number, ())
            yield tuple(cell.value for cell in row) if values_only else row


class Workbook:
    """Contexto somente leitura do pacote XLSX e suas abas de células."""

    def __init__(self, path: Path):
        self.path = path
        self.archive = None
        self.worksheets = []
        self.shared_strings = []

    def _xml(self, path: str):
        return ET.fromstring(self.archive.read(path))

    def _relationships(self, base: str):
        path = posixpath.join(posixpath.dirname(base), "_rels", posixpath.basename(base) + ".rels") if base else "_rels/.rels"
        relationships = {}
        for node in self._xml(path):
            if _local(node.tag) != "Relationship":
                continue
            identity = node.get("Id")
            if not identity or identity in relationships:
                raise ValueError("relacionamento sem identificador ou duplicado no XLSX")
            relationships[identity] = node
        return relationships

    def __enter__(self):
        try:
            self.archive = ZipFile(self.path)
            roots = [node for node in self._relationships("").values() if node.get("Type", "").endswith("/officeDocument")]
            if len(roots) != 1 or roots[0].get("TargetMode", "").lower() == "external":
                raise ValueError("documento principal XLSX ausente, ambíguo ou externo")
            workbook_path = _target("", roots[0].get("Target", ""))
            relationships = self._relationships(workbook_path)
            for relation in relationships.values():
                if relation.get("Type", "").endswith("/sharedStrings"):
                    if relation.get("TargetMode", "").lower() == "external":
                        raise ValueError("textos compartilhados externos não são suportados no XLSX")
                    root = self._xml(_target(workbook_path, relation.get("Target", "")))
                    self.shared_strings = [_string(node) for node in root if _local(node.tag) == "si"]
            for node in self._xml(workbook_path).iter():
                if _local(node.tag) != "sheet":
                    continue
                name = node.get("name")
                identity = next((value for key, value in node.attrib.items() if _local(key) == "id"), None)
                relation = relationships.get(identity)
                if not name or relation is None:
                    raise ValueError("aba sem nome ou relacionamento no XLSX")
                if relation.get("TargetMode", "").lower() == "external":
                    raise ValueError(f"aba {name!r} tem relacionamento externo; não será acessada")
                if not relation.get("Type", "").endswith("/worksheet"):
                    raise ValueError(f"tipo de aba não suportado no XLSX: {name!r}")
                if name in self.sheetnames:
                    raise ValueError("nomes de abas duplicados no XLSX")
                self.worksheets.append(Worksheet(self, name, _target(workbook_path, relation.get("Target", ""))))
            if not self.worksheets:
                raise ValueError("nenhuma aba de células encontrada no XLSX")
            return self
        except (BadZipFile, KeyError, ET.ParseError) as exc:
            self.close()
            raise ValueError(INVALID_XLSX_MESSAGE) from exc
        except BaseException:
            self.close()
            raise

    @property
    def sheetnames(self):
        return [sheet.title for sheet in self.worksheets]

    def __getitem__(self, name):
        return next(sheet for sheet in self.worksheets if sheet.title == name)

    def close(self):
        if self.archive is not None:
            self.archive.close()

    def __exit__(self, kind, value, traceback):
        self.close()
        if kind is not None and issubclass(kind, (BadZipFile, KeyError, ET.ParseError)):
            raise ValueError(INVALID_XLSX_MESSAGE) from value
