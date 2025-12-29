// Package storage provides repository implementations for Dideban data models.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Entity interface that all models must implement
type Entity interface {
	TableName() string
}

// Repository provides generic CRUD operations for any entity type.
type Repository[T Entity] struct {
	orm       *ORM
	tableName string
}

// NewRepository creates a new repository for type T.
func NewRepository[T Entity](orm *ORM) *Repository[T] {
	var zero T
	return &Repository[T]{
		orm:       orm,
		tableName: zero.TableName(),
	}
}

// Create inserts a new entity into the database.
func (r *Repository[T]) Create(ctx context.Context, entity T) (int64, error) {
	// Use reflection to build INSERT query dynamically
	v := reflect.ValueOf(entity)
	// If it's a pointer, get the underlying value
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	t := v.Type()

	var columns []string
	var placeholders []string
	var values []interface{}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		dbTag := field.Tag.Get("db")
		if dbTag == "" || dbTag == "-" || strings.Contains(dbTag, "auto_increment") {
			continue
		}

		columnName := strings.Split(dbTag, ",")[0]
		columns = append(columns, columnName)
		placeholders = append(placeholders, "?")

		fieldValue := v.Field(i)
		if field.Name == "CreatedAt" || field.Name == "UpdatedAt" {
			fieldValue.Set(reflect.ValueOf(time.Now()))
		}
		values = append(values, fieldValue.Interface())
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s)",
		r.tableName,
		strings.Join(columns, ", "),
		strings.Join(placeholders, ", "),
	)

	result, err := r.orm.db.ExecContext(ctx, query, values...)
	if err != nil {
		return 0, fmt.Errorf("failed to create %s: %w", r.tableName, err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get %s ID: %w", r.tableName, err)
	}

	// Set ID field if exists and entity is a pointer
	if reflect.ValueOf(entity).Kind() == reflect.Ptr {
		entityPtr := reflect.ValueOf(entity)
		if entityPtr.Kind() == reflect.Ptr && entityPtr.Elem().FieldByName("ID").IsValid() {
			entityPtr.Elem().FieldByName("ID").SetInt(id)
		}
	}

	log.Info().
		Int64("id", id).
		Str("table", r.tableName).
		Msg("Entity created")

	return id, nil
}

// GetByID retrieves an entity by its ID.
func (r *Repository[T]) GetByID(ctx context.Context, id int64) (*T, error) {
	entities, err := NewSelectBuilderFrom[T](r.orm, r.tableName).
		Where("id = ?", id).
		Execute(ctx)
	if err != nil {
		return nil, err
	}
	if len(entities) == 0 {
		return nil, sql.ErrNoRows
	}
	return &entities[0], nil
}

// GetAll retrieves all entities.
func (r *Repository[T]) GetAll(ctx context.Context) ([]T, error) {
	return NewSelectBuilderFrom[T](r.orm, r.tableName).
		OrderBy("id DESC").
		Execute(ctx)
}

// Update updates an existing entity.
func (r *Repository[T]) Update(ctx context.Context, entity T) error {
	v := reflect.ValueOf(entity)
	// If it's a pointer, get the underlying value
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	t := v.Type()

	var setParts []string
	var values []interface{}
	var id int64

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		dbTag := field.Tag.Get("db")
		if dbTag == "" || dbTag == "-" {
			continue
		}

		columnName := strings.Split(dbTag, ",")[0]
		fieldValue := v.Field(i)

		if columnName == "id" {
			id = fieldValue.Int()
			continue
		}

		if field.Name == "UpdatedAt" {
			fieldValue.Set(reflect.ValueOf(time.Now()))
		}

		setParts = append(setParts, columnName+" = ?")
		values = append(values, fieldValue.Interface())
	}

	values = append(values, id)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE id = ?",
		r.tableName,
		strings.Join(setParts, ", "),
	)

	_, err := r.orm.db.ExecContext(ctx, query, values...)
	if err != nil {
		return fmt.Errorf("failed to update %s: %w", r.tableName, err)
	}

	return nil
}

// Delete deletes an entity by ID.
func (r *Repository[T]) Delete(ctx context.Context, id int64) error {
	query := fmt.Sprintf("DELETE FROM %s WHERE id = ?", r.tableName)
	_, err := r.orm.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete %s: %w", r.tableName, err)
	}
	return nil
}

// Where adds a WHERE condition and returns entities.
func (r *Repository[T]) Where(ctx context.Context, condition string, args ...interface{}) ([]T, error) {
	return NewSelectBuilderFrom[T](r.orm, r.tableName).
		Where(condition, args...).
		Execute(ctx)
}

// First returns the first entity matching the condition.
func (r *Repository[T]) First(ctx context.Context, condition string, args ...interface{}) (*T, error) {
	entity, err := NewSelectBuilderFrom[T](r.orm, r.tableName).
		Where(condition, args...).
		First(ctx)
	if err != nil {
		return nil, err
	}
	return &entity, nil
}

// Count returns the number of entities matching the condition.
func (r *Repository[T]) Count(ctx context.Context, condition string, args ...interface{}) (int64, error) {
	builder := NewSelectBuilderFrom[T](r.orm, r.tableName)
	if condition != "" {
		builder = builder.Where(condition, args...)
	}
	return builder.Count(ctx)
}

// Repositories provides access to all repository instances.
type Repositories struct {
	Checks       *Repository[Check]
	CheckResults *Repository[CheckResult]
	Alerts       *Repository[Alert]
	Agents       *Repository[Agent]
	AgentMetrics *Repository[AgentMetric]
	Admins       *Repository[Admin]
}

// NewRepositories creates and initializes all repository instances.
func NewRepositories(orm *ORM) *Repositories {
	return &Repositories{
		Checks:       NewRepository[Check](orm),
		CheckResults: NewRepository[CheckResult](orm),
		Alerts:       NewRepository[Alert](orm),
		Agents:       NewRepository[Agent](orm),
		AgentMetrics: NewRepository[AgentMetric](orm),
		Admins:       NewRepository[Admin](orm),
	}
}
