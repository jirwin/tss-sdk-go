package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strconv"

	"github.com/jirwin/ctxzap"
	"go.uber.org/zap"
)

// resource is the HTTP URL path component for the secrets resource
const resource = "secrets"

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

// Secret gets the secret with id from the Secret Server of the given tenant
func (s *Server) Secret(ctx context.Context, id int) (*Secret, error) {
	l := ctxzap.Extract(ctx)
	secret := new(Secret)

	if data, err := s.accessResource(ctx, http.MethodGet, resource, strconv.Itoa(id), nil); err == nil {
		if err = json.Unmarshal(data, secret); err != nil {
			l.Error(
				"error parsing secret response",
				zap.Int("secret_id", id),
				zap.String("data", string(data)),
			)
			return nil, err
		}
	} else {
		return nil, err
	}

	// automatically download file attachments and substitute them for the
	// (dummy) ItemValue, so as to make the process transparent to the caller
	for index, element := range secret.Fields {
		if element.IsFile && element.FileAttachmentID != 0 && element.Filename != "" {
			resourcePath := path.Join(strconv.Itoa(id), "fields", element.Slug)

			if data, err := s.accessResource(ctx, http.MethodGet, resource, resourcePath, nil); err == nil {
				secret.Fields[index].ItemValue = string(data)
			} else {
				return nil, err
			}
		}
	}

	return secret, nil
}

// Secrets gets the secret with id from the Secret Server of the given tenant
func (s *Server) Secrets(ctx context.Context, searchText, field string) ([]Secret, error) {
	l := ctxzap.Extract(ctx)

	searchResult := new(SearchResult)
	if data, err := s.searchResources(ctx, resource, searchText, field); err == nil {
		if err = json.Unmarshal(data, searchResult); err != nil {
			l.Error("error parsing secret response", zap.String("search_text", searchText), zap.String("data", string(data)))
			return nil, err
		}
	} else {
		return nil, err
	}

	searchRecords := searchResult.Records
	secrets := make([]Secret, len(searchRecords))
	for i, record := range searchRecords {
		//secrets returned in search results are not fully populated
		secret, err := s.Secret(ctx, record.ID)
		if err != nil {
			return nil, err
		}
		secrets[i] = *secret
	}

	return secrets, nil
}

func (s *Server) CreateSecret(ctx context.Context, secret Secret) (*Secret, error) {
	return s.writeSecret(ctx, secret, http.MethodPost, "/")
}

func (s *Server) UpdateSecret(ctx context.Context, secret Secret) (*Secret, error) {
	l := ctxzap.Extract(ctx)

	if secret.SshKeyArgs != nil && (secret.SshKeyArgs.GenerateSshKeys || secret.SshKeyArgs.GeneratePassphrase) {
		l.Error("SSH key and passphrase generation is only supported during secret creation", zap.String("secret_name", secret.Name))
		return nil, errors.New("SSH key and passphrase generation is only supported during secret creation")
	}
	secret.SshKeyArgs = nil
	return s.writeSecret(ctx, secret, http.MethodPut, strconv.Itoa(secret.ID))
}

func (s *Server) writeSecret(ctx context.Context, secret Secret, method string, secretPath string) (*Secret, error) {
	l := ctxzap.Extract(ctx)
	writtenSecret := new(Secret)

	template, err := s.SecretTemplate(ctx, secret.SecretTemplateID)
	if err != nil {
		return nil, err
	}

	// If the user did not request SSH key generation, separate the
	// secret's fields into file fields and general fields, since we
	// need to take active control of either providing the files'
	// contents or deleting them. Otherwise, SSH key generation is
	// responsible for populating the contents of the file fields.
	//
	// NOTE!!! This implies support for *either* file contents provided
	// by the SSH generator *or* file contents provided by the user.
	// This SDK does support secret templates that accept both kinds
	// of file fields.
	fileFields := make([]SecretField, 0)
	generalFields := make([]SecretField, 0)
	if secret.SshKeyArgs == nil || !secret.SshKeyArgs.GenerateSshKeys {
		fileFields, generalFields, err = secret.separateFileFields(ctx, template)
		if err != nil {
			return nil, err
		}
		secret.Fields = generalFields
	}

	// If no SSH generation is called for, remove the SshKeyArgs value.
	// Simply having the value in the Secret object causes the
	// server to throw an error if the template is not geared towards
	// SSH key generation, even if both of the struct's members are
	// false.
	if secret.SshKeyArgs != nil {
		if !secret.SshKeyArgs.GenerateSshKeys && !secret.SshKeyArgs.GeneratePassphrase {
			secret.SshKeyArgs = nil
		}
	}

	// If the user specifies no items, perhaps because all the fields are
	// generated, apply an empty array to keep the server from rejecting the
	// request for missing a required element.
	if secret.Fields == nil {
		secret.Fields = make([]SecretField, 0)
	}

	if data, err := s.accessResource(ctx, method, resource, secretPath, secret); err == nil {
		if err = json.Unmarshal(data, writtenSecret); err != nil {
			l.Error("error parsing secret response", zap.String("secret_path", secretPath), zap.String("data", string(data)))
			return nil, err
		}
	} else {
		return nil, err
	}

	if err := s.updateFiles(ctx, writtenSecret.ID, fileFields); err != nil {
		return nil, err
	}

	return s.Secret(ctx, writtenSecret.ID)
}

func (s *Server) DeleteSecret(ctx context.Context, id int) error {
	_, err := s.accessResource(ctx, http.MethodDelete, resource, strconv.Itoa(id), nil)
	return err
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

// updateFiles iterates the list of file fields and if the field's item value is empty,
// deletes the file, otherwise, uploads the contents of the item value as the new/updated
// file attachment.
func (s *Server) updateFiles(ctx context.Context, secretId int, fileFields []SecretField) error {
	type fieldMod struct {
		Slug  string
		Dirty bool
		Value interface{}
	}

	type fieldMods struct {
		SecretFields []fieldMod
	}

	type secretPatch struct {
		Data fieldMods
	}

	for _, element := range fileFields {
		var elementPath string
		var input interface{}
		if element.ItemValue == "" {
			elementPath = path.Join(strconv.Itoa(secretId), "general")
			input = secretPatch{Data: fieldMods{SecretFields: []fieldMod{{Slug: element.Slug, Dirty: true, Value: nil}}}}
			if _, err := s.accessResource(ctx, http.MethodPatch, resource, elementPath, input); err != nil {
				return err
			}
		} else {
			if err := s.uploadFile(ctx, secretId, element); err != nil {
				return err
			}
		}
	}
	return nil
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
