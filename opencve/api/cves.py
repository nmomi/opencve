from flask import abort, request
from flask_restful import fields, marshal_with

from opencve.api.base import BaseResource
from opencve.api.fields import CveVendorsField, DatetimeField
from opencve.controllers.cves import CveController


cve_base_fields = {
    "id": fields.String(attribute="cve_id"),
    "summary": fields.String(attribute="summary"),
    "created_at": DatetimeField(),
    "updated_at": DatetimeField(),
}

cve_fields = dict(
    cve_base_fields,
    **{
        "cvss": {
            "v2": fields.Float(attribute="cvss2"),
            "v3": fields.Float(attribute="cvss3"),
        },
        "vendors": CveVendorsField(attribute="json"),
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


class CveTestResource(BaseResource):
    @marshal_with(cves_fields)
    def get(self):
        result = CveController.list_test(request.args)
        print(result)
        return result
