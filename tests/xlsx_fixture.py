"""Construtor mínimo de XLSX para os testes, sem dependências externas."""

from xml.etree import ElementTree as ET
from zipfile import ZipFile, ZIP_DEFLATED


MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PACKAGE_REL = "http://schemas.openxmlformats.org/package/2006/relationships"


def _column(number):
    letters = ""
    while number:
        number, remainder = divmod(number - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters


def _xml(element):
    return ET.tostring(element, encoding="utf-8", xml_declaration=True)


class Worksheet:
    def __init__(self, title):
        self.title = title
        self.sheet_state = "visible"
        self.rows = []

    def append(self, row):
        self.rows.append(list(row))


class Workbook:
    def __init__(self):
        self.worksheets = [Worksheet("Sheet")]

    @property
    def active(self):
        return self.worksheets[0]

    def create_sheet(self, title):
        sheet = Worksheet(title)
        self.worksheets.append(sheet)
        return sheet

    def close(self):
        pass

    def save(self, path):
        content_types = ET.Element("Types", xmlns="http://schemas.openxmlformats.org/package/2006/content-types")
        ET.SubElement(content_types, "Default", Extension="rels", ContentType="application/vnd.openxmlformats-package.relationships+xml")
        ET.SubElement(content_types, "Default", Extension="xml", ContentType="application/xml")
        ET.SubElement(content_types, "Override", PartName="/xl/workbook.xml", ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml")
        root_rels = ET.Element("Relationships", xmlns=PACKAGE_REL)
        ET.SubElement(root_rels, "Relationship", Id="rId1", Type=REL + "/officeDocument", Target="xl/workbook.xml")
        workbook = ET.Element("workbook", xmlns=MAIN, attrib={"xmlns:r": REL})
        sheets = ET.SubElement(workbook, "sheets")
        relationships = ET.Element("Relationships", xmlns=PACKAGE_REL)
        with ZipFile(path, "w", compression=ZIP_DEFLATED) as archive:
            archive.writestr("_rels/.rels", _xml(root_rels))
            for index, sheet in enumerate(self.worksheets, 1):
                identity = f"rId{index}"
                ET.SubElement(sheets, "sheet", name=sheet.title, sheetId=str(index), state=sheet.sheet_state, attrib={"r:id": identity})
                ET.SubElement(relationships, "Relationship", Id=identity, Type=REL + "/worksheet", Target=f"worksheets/sheet{index}.xml")
                ET.SubElement(content_types, "Override", PartName=f"/xl/worksheets/sheet{index}.xml", ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml")
                worksheet = ET.Element("worksheet", xmlns=MAIN)
                max_column = max((len(row) for row in sheet.rows), default=1)
                ET.SubElement(worksheet, "dimension", ref=f"A1:{_column(max_column)}{max(1, len(sheet.rows))}")
                data = ET.SubElement(worksheet, "sheetData")
                for row_number, values in enumerate(sheet.rows, 1):
                    row = ET.SubElement(data, "row", r=str(row_number))
                    for column, value in enumerate(values, 1):
                        if value is None:
                            continue
                        cell = ET.SubElement(row, "c", r=f"{_column(column)}{row_number}")
                        if isinstance(value, str):
                            if value.startswith("="):
                                ET.SubElement(cell, "f").text = value[1:]
                            else:
                                cell.set("t", "inlineStr")
                                ET.SubElement(ET.SubElement(cell, "is"), "t").text = value
                        elif isinstance(value, bool):
                            cell.set("t", "b")
                            ET.SubElement(cell, "v").text = str(int(value))
                        else:
                            ET.SubElement(cell, "v").text = str(value)
                archive.writestr(f"xl/worksheets/sheet{index}.xml", _xml(worksheet))
            archive.writestr("xl/workbook.xml", _xml(workbook))
            archive.writestr("xl/_rels/workbook.xml.rels", _xml(relationships))
            archive.writestr("[Content_Types].xml", _xml(content_types))
