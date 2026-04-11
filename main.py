from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from docxtpl import DocxTemplate
from typing import List, Optional
import io
import zipfile
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")


# ─── Модели данных (что приходит с формы) ───────────────────────────────────

class Service(BaseModel):
    service_name: str
    service_period: str
    service_cost: str

class ContractData(BaseModel):
    # Какие договоры генерировать
    generate_license: bool = False
    generate_services: bool = False

    # Общие поля
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

    # Только для лицензионного
    report_period: str = ""
    employees_count: str = ""
    license_cost: str = ""

    # Только для договора услуг
    services: Optional[List[Service]] = []
    total_cost: str = ""


# ─── Эндпоинт генерации ─────────────────────────────────────────────────────

@app.post("/generate")
async def generate(data: ContractData):
    if not data.generate_license and not data.generate_services:
        raise HTTPException(status_code=400, detail="Выберите хотя бы один договор")

    # Создаём ZIP-архив в памяти (не сохраняем на диск)
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
            filename = f"Договор_лицензионный_{data.company_name}.docx"
            zf.writestr(filename, doc_bytes)

        if data.generate_services:
            # Преобразуем список услуг в формат для docxtpl
            services_list = [
                {
                    "service_name":   s.service_name,
                    "service_period": s.service_period,
                    "service_cost":   s.service_cost,
                }
                for s in (data.services or [])
            ]
            doc_bytes = fill_template("contract_services.docx", {
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
                "services":           services_list,
                "total_cost":         data.total_cost,
            })
            filename = f"Договор_услуги_{data.company_name}.docx"
            zf.writestr(filename, doc_bytes)

    zip_buffer.seek(0)

    filename_zip = f"Договоры_{data.company_name}_№{data.contract_number}.zip"

    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{filename_zip}"}
    )


def fill_template(template_name: str, context: dict) -> bytes:
    """Заполняет шаблон данными и возвращает байты готового файла"""
    template_path = os.path.join(TEMPLATES_DIR, template_name)

    if not os.path.exists(template_path):
        raise HTTPException(status_code=404, detail=f"Шаблон {template_name} не найден")

    doc = DocxTemplate(template_path)
    doc.render(context)

    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer.read()


# ─── Раздаём статику (HTML форму) ───────────────────────────────────────────

app.mount("/", StaticFiles(directory="static", html=True), name="static")
