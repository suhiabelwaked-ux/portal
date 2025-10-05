from marshmallow import Schema, fields, validate

class FindingSchema(Schema):
    id = fields.Int()
    finding_number = fields.Str()
    title = fields.Str()
    description = fields.Str()
    recommendation = fields.Str()
    status = fields.Str()
    created_at = fields.DateTime()

class ReviewSessionSchema(Schema):
    id = fields.Int()
    session_key = fields.Str()
    filename = fields.Str()
    status = fields.Str()
    created_at = fields.DateTime()
    findings = fields.Nested(FindingSchema, many=True)

class UpdateFindingSchema(Schema):
    status = fields.Str(required=True, validate=validate.OneOf(['pass', 'fail', 'pending']))

class CreateReviewSessionSchema(Schema):
    filename = fields.Str(required=True)