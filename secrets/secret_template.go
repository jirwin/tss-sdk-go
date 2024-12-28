package secrets

import (
	"context"

	"github.com/jirwin/ctxzap"
	"go.uber.org/zap"
)

// SecretTemplate represents a secret template from Delinea Secret Server
type SecretTemplate struct {
	Name   string
	ID     int
	Fields []SecretTemplateField
}

// SecretTemplateField is a field in the secret template
type SecretTemplateField struct {
	SecretTemplateFieldID                                   int
	FieldSlugName, DisplayName, Description, Name, ListType string
	IsFile, IsList, IsNotes, IsPassword, IsRequired, IsUrl  bool
}

// FieldIdToSlug returns the shorthand alias (aka: "slug") of the field with the given field ID, and a boolean
// indicating whether the given ID actually identifies a field for the secret template.
func (s *SecretTemplate) FieldIdToSlug(ctx context.Context, fieldId int) (string, bool) {
	l := ctxzap.Extract(ctx)
	for _, field := range s.Fields {
		if fieldId == field.SecretTemplateFieldID {
			l.Debug("template field with slug matches the given ID", zap.String("slug", field.FieldSlugName), zap.Int("id", fieldId))
			return field.FieldSlugName, true
		}
	}
	l.Error("no matching template field with ID", zap.Int("id", fieldId), zap.String("template_name", s.Name))
	return "", false
}

// FieldSlugToId returns the field ID for the given shorthand alias (aka: "slug") of the field, and a boolean indicating
// whether the given slug actually identifies a field for the secret template.
func (s *SecretTemplate) FieldSlugToId(ctx context.Context, slug string) (int, bool) {
	field, found := s.GetField(ctx, slug)
	if found {
		return field.SecretTemplateFieldID, found
	}
	return 0, found
}

// GetField returns the field with the given shorthand alias (aka: "slug"), and a boolean indicating whether the given
// slug actually identifies a field for the secret template .
func (s *SecretTemplate) GetField(ctx context.Context, slug string) (*SecretTemplateField, bool) {
	l := ctxzap.Extract(ctx)

	for _, field := range s.Fields {
		if slug == field.FieldSlugName {
			l.Debug("template field with ID matches the given slug", zap.Int("id", field.SecretTemplateFieldID), zap.String("slug", slug))
			return &field, true
		}
	}

	l.Error("no matching template field with slug", zap.String("slug", slug), zap.String("template_name", s.Name))
	return nil, false
}
