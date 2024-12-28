package secrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/jirwin/ctxzap"
	"go.uber.org/zap"
)

// Secret represents a secret from Delinea Secret Server
type Secret struct {
	Name                                                                       string
	FolderID, ID, SiteID, SecretTemplateID                                     int
	SecretPolicyID, PasswordTypeWebScriptID                                    int `json:",omitempty"`
	LauncherConnectAsSecretID, CheckOutIntervalMinutes                         int
	Active, CheckedOut, CheckOutEnabled                                        bool
	AutoChangeEnabled, CheckOutChangePasswordEnabled, DelayIndexing            bool
	EnableInheritPermissions, EnableInheritSecretPolicy, ProxyEnabled          bool
	RequiresComment, SessionRecordingEnabled, WebLauncherRequiresIncognitoMode bool
	Fields                                                                     []SecretField `json:"Items"`
	SshKeyArgs                                                                 *SshKeyArgs   `json:",omitempty"`
}

// SecretField is an item (field) in the secret
type SecretField struct {
	ItemID, FieldID, FileAttachmentID     int
	FieldName, Slug                       string
	FieldDescription, Filename, ItemValue string
	IsFile, IsNotes, IsPassword           bool
}

type SearchResult struct {
	SearchText string
	Records    []Secret
}

// SshKeyArgs control whether to generate an SSH key pair and a private key
// passphrase when the secret template supports such generation.
//
// WARNING: this struct is only used for write _request_ bodies, and will not
// be present in _response_ bodies.
type SshKeyArgs struct {
	GeneratePassphrase, GenerateSshKeys bool
}

// Field returns the value of the field with the name fieldName
func (s *Secret) Field(ctx context.Context, fieldName string) (string, bool) {
	l := ctxzap.Extract(ctx)
	for _, field := range s.Fields {
		if fieldName == field.FieldName || fieldName == field.Slug {
			l.Debug("field with name matches", zap.String("field_name", field.FieldName), zap.String("field_slug", field.Slug))
			return field.ItemValue, true
		}
	}

	l.Debug("no matching field", zap.String("field_name", fieldName), zap.String("secret_name", s.Name))
	return "", false
}

// FieldById returns the value of the field with the given field ID
func (s *Secret) FieldById(ctx context.Context, fieldId int) (string, bool) {
	l := ctxzap.Extract(ctx)
	for _, field := range s.Fields {
		if fieldId == field.FieldID {
			l.Debug("field with name matches", zap.String("field_name", field.FieldName), zap.Int("field_id", field.FieldID))
			return field.ItemValue, true
		}
	}

	l.Debug("no matching field", zap.Int("field_id", fieldId), zap.String("secret_name", s.Name))
	return "", false
}

// separateFileFields iterates the fields on this secret, and separates them into file
// fields and non-file fields, using the field definitions in the given template as a
// guide. File fields are returned as the first output, non file fields as the second
// output.
func (s *Secret) separateFileFields(ctx context.Context, template *SecretTemplate) ([]SecretField, []SecretField, error) {
	l := ctxzap.Extract(ctx)

	var fileFields []SecretField
	var nonFileFields []SecretField

	for _, field := range s.Fields {
		var templateField *SecretTemplateField
		var found bool
		fieldSlug := field.Slug
		if fieldSlug == "" {
			if fieldSlug, found = template.FieldIdToSlug(ctx, field.FieldID); !found {
				l.Error("field id is not defined on the secret template", zap.Int("field_id", field.FieldID), zap.Int("template_id", template.ID))
				return nil, nil, fmt.Errorf("[ERROR] field id '%d' is not defined on the secret template with id '%d'", field.FieldID, template.ID)
			}
		}
		if templateField, found = template.GetField(ctx, fieldSlug); !found {
			l.Error("field name is not defined on the secret template", zap.String("field_name", fieldSlug), zap.Int("template_id", template.ID))
			return nil, nil, errors.New("error: field name is not defined on the secret template")
		}
		if templateField.IsFile {
			fileFields = append(fileFields, field)
		} else {
			nonFileFields = append(nonFileFields, field)
		}
	}

	return fileFields, nonFileFields, nil
}
