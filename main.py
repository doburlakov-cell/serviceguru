from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from docxtpl import DocxTemplate
from typing import List, Optional
from urllib.parse import quote
import zipfile
import re
import io
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")


# ─── Модели данных ───────────────────────────────────────────────────────────

class Service(BaseModel):
    service_name: str
    service_period: str
    service_cost: str

class ContractData(BaseModel):
    generate_license: bool = False
    generate_services: bool = False
    contract_number: str
    date: str
    manager_name: str = ""
    client_email: str = ""
    company_name: str
    client_short_name: str = ""
    director_full_name: str = ""
    director_genitive: str = ""
    legal_address: str = ""
    postal_address: str = ""
    ogrn: str = ""
    inn: str = ""
    kpp: str = ""
    bik: str = ""
    bank_name: str = ""
    bank_account: str = ""
    corr_account: str = ""
    report_period: str = ""
    employees_count: str = ""
    license_cost: str = ""
    services: Optional[List[Service]] = []
    total_cost: str = ""


# ─── Генерация ───────────────────────────────────────────────────────────────

@app.post("/generate")
async def generate(data: ContractData):
    if not data.generate_license and not data.generate_services:
        raise HTTPException(status_code=400, detail="Выберите хотя бы один договор")

    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:

        if data.generate_license:
            doc_bytes = fill_template("contract_license.docx", {
                "contract_number":    data.contract_number,
                "date":               data.date,
                "manager_name":       data.manager_name,
                "client_email":       data.client_email,
                "company_name":       data.company_name,
                "client_short_name":  data.client_short_name,
                "director_full_name": data.director_full_name,
                "director_genitive":  data.director_genitive,
                "legal_address":      data.legal_address,
                "postal_address":     data.postal_address,
                "ogrn":               data.ogrn,
                "inn":                data.inn,
                "kpp":                data.kpp,
                "bik":                data.bik,
                "bank_name":          data.bank_name,
                "bank_account":       data.bank_account,
                "corr_account":       data.corr_account,
                "report_period":      data.report_period,
                "employees_count":    data.employees_count,
                "license_cost":       data.license_cost,
            })
            zf.writestr(f"Договор_лицензионный_{data.company_name}.docx", doc_bytes)

        if data.generate_services:
            services = [s.dict() for s in (data.services or [])]
            doc_bytes = fill_services_template(
                "contract_services.docx",
                context={
                    "contract_number":    data.contract_number,
                    "date":               data.date,
                    "company_name":       data.company_name,
                    "client_short_name":  data.client_short_name,
                    "director_full_name": data.director_full_name,
                    "director_genitive":  data.director_genitive,
                    "legal_address":      data.legal_address,
                    "postal_address":     data.postal_address,
                    "ogrn":               data.ogrn,
                    "inn":                data.inn,
                    "kpp":                data.kpp,
                    "bik":                data.bik,
                    "bank_name":          data.bank_name,
                    "bank_account":       data.bank_account,
                    "corr_account":       data.corr_account,
                    "total_cost":         data.total_cost,
                },
                services=services,
            )
            zf.writestr(f"Договор_услуги_{data.company_name}.docx", doc_bytes)

    zip_buffer.seek(0)
    filename_zip = f"Договоры_{data.company_name}_№{data.contract_number}.zip"
    filename_encoded = quote(filename_zip, safe='')

    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{filename_encoded}"}
    )


# ─── Заполнение обычного шаблона ─────────────────────────────────────────────

def fill_template(template_name: str, context: dict) -> bytes:
    template_path = os.path.join(TEMPLATES_DIR, template_name)
    if not os.path.exists(template_path):
        raise HTTPException(status_code=404, detail=f"Шаблон {template_name} не найден")
    doc = DocxTemplate(template_path)
    doc.render(context)
    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf.read()


# ─── Заполнение шаблона услуг с дублированием строк ─────────────────────────

def fill_services_template(template_name: str, context: dict, services: list) -> bytes:
    template_path = os.path.join(TEMPLATES_DIR, template_name)
    if not os.path.exists(template_path):
        raise HTTPException(status_code=404, detail=f"Шаблон {template_name} не найден")

    # Читаем docx
    with zipfile.ZipFile(template_path, 'r') as z:
        all_files = {name: z.read(name) for name in z.namelist()}

    xml = all_files['word/document.xml'].decode('utf-8')

    # Дублируем строки таблицы для каждой услуги
    xml = duplicate_service_rows(xml, services)

    # Пересобираем docx во временный буфер
    tmp = io.BytesIO()
    with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data in all_files.items():
            if name == 'word/document.xml':
                z.writestr(name, xml.encode('utf-8'))
            else:
                z.writestr(name, data)
    tmp.seek(0)

    # Заполняем простые переменные через docxtpl
    doc = DocxTemplate(tmp)
    doc.render(context)
    out = io.BytesIO()
    doc.save(out)
    out.seek(0)
    return out.read()


def duplicate_service_rows(xml: str, services: list) -> str:
    """
    Находит строки таблицы с {{service_name}} и дублирует их
    для каждой услуги, подставляя данные напрямую в XML.
    """
    if not services:
        services = [{"service_name": "", "service_cost": "", "service_period": ""}]

    tr_pattern = re.compile(r'<w:tr[ >].*?</w:tr>', re.DOTALL)
    matches = list(tr_pattern.finditer(xml))

    result = xml
    # Обрабатываем в обратном порядке — чтобы позиции не сбивались
    for match in reversed(matches):
        tr = match.group(0)
        if '{{service_name}}' not in tr:
            continue
        rows = []
        for svc in services:
            row = tr
            row = row.replace('{{service_name}}',   escape_xml(svc.get('service_name', '')))
            row = row.replace('{{service_cost}}',    escape_xml(svc.get('service_cost', '')))
            row = row.replace('{{service_period}}',  escape_xml(svc.get('service_period', '')))
            rows.append(row)
        result = result[:match.start()] + ''.join(rows) + result[match.end():]

    return result


def escape_xml(text: str) -> str:
    """Экранирует спецсимволы XML"""
    return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;'))


# ─── Статика ─────────────────────────────────────────────────────────────────

app.mount("/", StaticFiles(directory="static", html=True), name="static")
