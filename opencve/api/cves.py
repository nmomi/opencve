from flask import abort, request
from flask_restful import fields, marshal_with

from opencve.api.base import BaseResource
from opencve.api.fields import CveVendorsField, DatetimeField
from opencve.controllers.cves import CveController


def get_cvss_severity(cvss3_value):
    if cvss3_value is None:
        return "None"
    elif 0.1 <= cvss3_value <= 3.9:
        return "Low"
    elif 4.0 <= cvss3_value <= 6.9:
        return "Medium"
    elif 7.0 <= cvss3_value <= 8.9:
        return "High"
    elif 9.0 <= cvss3_value <= 10.0:
        return "Critical"
    else:
        return "Unknown"


cve_base_fields = {
    "id": fields.String(attribute="cve_id"),
    "summary": fields.String(attribute="summary"),
    "created_at": DatetimeField(),
    "updated_at": DatetimeField(),
    "cvss": {
        "v2": fields.Float(attribute="cvss2"),
        "v3": fields.Float(attribute="cvss3"),
        "severity": fields.String(attribute=lambda x: get_cvss_severity(x.cvss3))
    },
    "vendors": CveVendorsField(attribute="json")
}

cve_fields = dict(
    cve_base_fields,
    **{
        "cwes": fields.Raw(),
        "raw_nvd_data": fields.Raw(attribute="json"),
    }
)

cves_fields = {
    "total": fields.Integer,
    "items": fields.List(fields.Nested(cve_base_fields))
}


class CveListResource(BaseResource):
    @marshal_with(cves_fields)
    def get(self):
        return CveController.list_items(request.args)


class CveResource(BaseResource):
    @marshal_with(cve_fields)
    def get(self, id):
        return CveController.get({"cve_id": id})
