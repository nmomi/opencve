from flask import request
from flask_restful import fields, marshal_with

from opencve.api.base import BaseResource
from opencve.controllers.products import ProductController
from opencve.controllers.vendors import VendorController
from opencve.api.fields import HumanizedNameField


def get_products_count(vendor):
    return len(vendor.products)


vendor_list_fields = {
    "id": fields.String(attribute="id"),
    "name": fields.String(attribute="name"),
    "human_name": HumanizedNameField(attribute="name"),
}

vendor_products_fields = {
    "id": fields.String(attribute="id"),
    "name": fields.String(attribute="name"),
    "human_name": HumanizedNameField(attribute="name"),
    "vendor": fields.Nested(vendor_list_fields),
}

vendor_list_fields = {
    "total": fields.Integer,
    "items": fields.List(
        fields.Nested(
            {
                **vendor_list_fields,
                "products_count": fields.Integer(attribute=get_products_count),
            }
        )
    ),
}

product_list_fields = {
    "total": fields.Integer,
    "items": fields.List(fields.Nested(vendor_products_fields)),
}


class MyVendorResource(BaseResource):
    @marshal_with(vendor_list_fields)
    def get(self):
        vendors, _, _ = VendorController.list(request.args)
        return {"total": vendors.total, "items": vendors.items}


class MyProductResource(BaseResource):
    @marshal_with(product_list_fields)
    def get(self):
        products, _, _ = ProductController.list(
            {**request.args, "product_page": request.args.get("page", 1)}
        )
        return {"total": products.total, "items": products.items}
