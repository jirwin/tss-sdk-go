package server

import (
	"context"
	"encoding/json"
	"net/http"
	"path"
	"strconv"

	"github.com/jirwin/ctxzap"
	"go.uber.org/zap"
)

// templateResource is the HTTP URL path component for the secret templates resource
const templateResource = "secret-templates"

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

// SecretTemplate gets the secret template with id from the Secret Server of the given tenant
func (s *Server) SecretTemplate(ctx context.Context, id int) (*SecretTemplate, error) {
	l := ctxzap.Extract(ctx)
	secretTemplate := new(SecretTemplate)

	if data, err := s.accessResource(ctx, http.MethodGet, templateResource, strconv.Itoa(id), nil); err == nil {
		if err = json.Unmarshal(data, secretTemplate); err != nil {
			l.Error("error parsing secret template response", zap.Int("secret_template_id", id), zap.String("data", string(data)))
			return nil, err
		}
	} else {
		return nil, err
	}

	return secretTemplate, nil
}

// GeneratePassword generates and returns a password for the secret field identified by the given slug on the given
// template. The password adheres to the password requirements associated with the field. NOTE: this should only be
// used with fields whose IsPassword property is true.
func (s *Server) GeneratePassword(ctx context.Context, slug string, template *SecretTemplate) (string, error) {
	l := ctxzap.Extract(ctx)
	fieldId, found := template.FieldSlugToId(ctx, slug)

	if !found {
		l.Error("the alias does not identify a field on the template", zap.String("alias", slug), zap.String("template_name", template.Name))
	}
	resourcePath := path.Join("generate-password", strconv.Itoa(fieldId))

	if data, err := s.accessResource(ctx, http.MethodPost, templateResource, resourcePath, nil); err == nil {
		passwordWithQuotes := string(data)
		return passwordWithQuotes[1 : len(passwordWithQuotes)-1], nil
	} else {
		return "", err
	}
}

// FieldIdToSlug returns the shorthand alias (aka: "slug") of the field with the given field ID, and a boolean
// indicating whether the given ID actually identifies a field for the secret template.
func (s SecretTemplate) FieldIdToSlug(ctx context.Context, fieldId int) (string, bool) {
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
func (s SecretTemplate) FieldSlugToId(ctx context.Context, slug string) (int, bool) {
	field, found := s.GetField(ctx, slug)
	if found {
		return field.SecretTemplateFieldID, found
	}
	return 0, found
}

// GetField returns the field with the given shorthand alias (aka: "slug"), and a boolean indicating whether the given
// slug actually identifies a field for the secret template .
func (s SecretTemplate) GetField(ctx context.Context, slug string) (*SecretTemplateField, bool) {
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
