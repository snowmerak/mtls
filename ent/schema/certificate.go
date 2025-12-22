package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Certificate holds the schema definition for the Certificate entity.
type Certificate struct {
	ent.Schema
}

// Fields of the Certificate.
func (Certificate) Fields() []ent.Field {
	return []ent.Field{
		field.String("common_name"),
		field.String("serial_number"),
		field.Enum("type").Values("root_ca", "intermediate_ca", "server", "client"),
		field.Enum("status").Values("valid", "revoked", "expired").Default("valid"),
		field.Time("created_at").Default(time.Now),
		field.Time("expires_at"),
		field.Time("revoked_at").Optional().Nillable(),
		field.String("key_type"),
		field.String("fingerprint"),
		field.String("cert_path"),
		field.String("key_path"),
		field.String("organization").Optional(),
		field.String("country").Optional(),
		field.JSON("dns_names", []string{}).Optional(),
		field.JSON("ip_addresses", []string{}).Optional(),
		field.Bool("is_ca").Default(false),
	}
}

// Edges of the Certificate.
func (Certificate) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("children", Certificate.Type).
			From("issuer").
			Unique(),
	}
}
