from marshmallow import Schema, fields, validate

class LoginSchema(Schema):
    username = fields.Str(required=True, validate=validate.Length(min=1, max=80))
    password = fields.Str(required=True, validate=validate.Length(min=1))

class UserSchema(Schema):
    id = fields.Int()
    username = fields.Str()
    status = fields.Str()
    created_at = fields.DateTime()

class CreateUserSchema(Schema):
    username = fields.Str(required=True, validate=validate.Length(min=1, max=80))
    password = fields.Str(required=True, validate=validate.Length(min=6))
    status = fields.Str(validate=validate.OneOf(['enabled', 'disabled']))
    is_admin = fields.Bool()

class UpdateUserSchema(Schema):
    status = fields.Str(validate=validate.OneOf(['enabled', 'disabled']))
    password = fields.Str(validate=validate.Length(min=6))
    is_admin = fields.Bool()