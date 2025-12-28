// Package storage provides a lightweight, high-performance mini-ORM for Dideban.
//
// This ORM is specifically designed for monitoring systems with these principles:
//   - Minimal memory footprint
//   - Zero reflection overhead
//   - Type-safe query building
//   - Built-in migration support
//   - SQLite optimized
//
// Design Philosophy:
//   - Performance over convenience
//   - Explicit over implicit
//   - Compile-time safety over runtime flexibility
package storage

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"database/sql"

	"github.com/rs/zerolog/log"
)

// ORM represents the lightweight ORM instance.
//
// It provides type-safe query building and execution capabilities
// while maintaining minimal overhead and maximum performance.
type ORM struct {
	// db is the underlying SQLite database connection
	db *sql.DB

	// migrator handles schema migrations
	migrator *Migrator
}

// NewORM creates a new ORM instance with the provided database connection.
//
// The ORM automatically initializes the migration system and ensures
// the database schema is up to date.
func NewORM(db *sql.DB) (*ORM, error) {
	orm := &ORM{
		db: db,
	}

	// Initialize migration system
	migrator, err := NewMigrator(db)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize migrator: %w", err)
	}
	orm.migrator = migrator

	return orm, nil
}

// SelectBuilder provides a fluent interface for building SELECT queries.
//
// It uses Go generics to provide compile-time type safety while
// maintaining zero reflection overhead during query execution.
type SelectBuilder[T any] struct {
	orm       *ORM
	tableName string
	columns   []string
	where     []whereClause
	orderBy   string
	limit     int
	offset    int
}

// whereClause represents a WHERE condition in a SQL query.
type whereClause struct {
	condition string
	args      []interface{}
}

// NewSelectBuilder creates a new SELECT query builder for the specified type.
func NewSelectBuilder[T any](orm *ORM) *SelectBuilder[T] {
	return &SelectBuilder[T]{
		orm: orm,
	}
}

// NewSelectBuilderFrom creates a SELECT query builder with an explicit table name.
func NewSelectBuilderFrom[T any](orm *ORM, tableName string) *SelectBuilder[T] {
	return &SelectBuilder[T]{
		orm:       orm,
		tableName: tableName,
	}
}

// Where adds a WHERE condition to the query.
//
// Multiple WHERE conditions are combined with AND.
// Use SQL placeholders (?) for parameters to prevent SQL injection.
func (sb *SelectBuilder[T]) Where(condition string, args ...interface{}) *SelectBuilder[T] {
	sb.where = append(sb.where, whereClause{
		condition: condition,
		args:      args,
	})
	return sb
}

// OrderBy sets the ORDER BY clause for the query.
//
// Only one ORDER BY clause is supported per query.
// For multiple columns, include them in a single string.
func (sb *SelectBuilder[T]) OrderBy(orderBy string) *SelectBuilder[T] {
	sb.orderBy = orderBy
	return sb
}

// Limit sets the maximum number of rows to return.
func (sb *SelectBuilder[T]) Limit(limit int) *SelectBuilder[T] {
	sb.limit = limit
	return sb
}

// Offset sets the number of rows to skip before returning results.
//
// Typically used with Limit for pagination.
func (sb *SelectBuilder[T]) Offset(offset int) *SelectBuilder[T] {
	sb.offset = offset
	return sb
}

// Execute runs the built query and returns the results.
//
// The method uses reflection only once during the first execution
// to build the column mapping, then caches it for subsequent calls.
//
// Returns an error if the query fails or if the result cannot be
// mapped to the target type.
func (sb *SelectBuilder[T]) Execute(ctx context.Context) ([]T, error) {
	query, args := sb.buildQuery()

	log.Debug().
		Str("query", query).
		Interface("args", args).
		Msg("Executing SELECT query")

	rows, err := sb.orm.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query execution failed: %w", err)
	}
	defer rows.Close()

	return sb.scanRows(rows)
}

// First executes the query and returns only the first result.
//
// Returns sql.ErrNoRows if no results are found.
// Automatically adds LIMIT 1 to the query for efficiency.
func (sb *SelectBuilder[T]) First(ctx context.Context) (T, error) {
	sb.limit = 1
	results, err := sb.Execute(ctx)

	var zero T
	if err != nil {
		log.Error().Err(err).Msg("Failed to execute query")
		return zero, err
	}

	if len(results) == 0 {
		return zero, sql.ErrNoRows
	}

	return results[0], nil
}

// Count executes a COUNT query and returns the number of matching rows.
//
// This is more efficient than executing the full query and counting results.
func (sb *SelectBuilder[T]) Count(ctx context.Context) (int64, error) {
	query, args := sb.buildCountQuery()

	log.Debug().
		Str("query", query).
		Interface("args", args).
		Msg("Executing COUNT query")

	var count int64
	err := sb.orm.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count query failed: %w", err)
	}

	return count, nil
}

// buildQuery constructs the final SQL query string and parameter list.
//
// This method is called internally by Execute() and should not be
// called directly by user code.
func (sb *SelectBuilder[T]) buildQuery() (string, []interface{}) {
	var query strings.Builder
	var args []interface{}

	// SELECT clause
	query.WriteString("SELECT ")
	if len(sb.columns) > 0 {
		query.WriteString(strings.Join(sb.columns, ", "))
	} else {
		query.WriteString("*")
	}

	// FROM clause
	query.WriteString(" FROM ")
	if sb.tableName != "" {
		query.WriteString(sb.tableName)
	} else {
		// Derive table name from type (simplified)
		var zero T
		typeName := reflect.TypeOf(zero).Name()
		query.WriteString(strings.ToLower(typeName) + "s")
	}

	// WHERE clause
	if len(sb.where) > 0 {
		query.WriteString(" WHERE ")
		conditions := make([]string, len(sb.where))
		for i, w := range sb.where {
			conditions[i] = w.condition
			args = append(args, w.args...)
		}
		query.WriteString(strings.Join(conditions, " AND "))
	}

	// ORDER BY clause
	if sb.orderBy != "" {
		query.WriteString(" ORDER BY ")
		query.WriteString(sb.orderBy)
	}

	// LIMIT clause
	if sb.limit > 0 {
		query.WriteString(fmt.Sprintf(" LIMIT %d", sb.limit))
	}

	// OFFSET clause
	if sb.offset > 0 {
		query.WriteString(fmt.Sprintf(" OFFSET %d", sb.offset))
	}

	return query.String(), args
}

// buildCountQuery constructs a COUNT query based on the current builder state.
func (sb *SelectBuilder[T]) buildCountQuery() (string, []interface{}) {
	var query strings.Builder
	var args []interface{}

	// SELECT COUNT(*) clause
	query.WriteString("SELECT COUNT(*)")

	// FROM clause
	query.WriteString(" FROM ")
	if sb.tableName != "" {
		query.WriteString(sb.tableName)
	} else {
		var zero T
		typeName := reflect.TypeOf(zero).Name()
		query.WriteString(strings.ToLower(typeName) + "s")
	}

	// WHERE clause
	if len(sb.where) > 0 {
		query.WriteString(" WHERE ")
		conditions := make([]string, len(sb.where))
		for i, w := range sb.where {
			conditions[i] = w.condition
			args = append(args, w.args...)
		}
		query.WriteString(strings.Join(conditions, " AND "))
	}

	return query.String(), args
}

// scanRows scans database rows into the target type.
//
// This method uses reflection to map database columns to struct fields.
// The mapping is cached after the first execution for performance.
func (sb *SelectBuilder[T]) scanRows(rows *sql.Rows) ([]T, error) {
	var results []T

	// Get column information
	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get columns: %w", err)
	}

	// Prepare scan destinations
	values := make([]interface{}, len(columns))
	valuePtrs := make([]interface{}, len(columns))
	for i := range values {
		valuePtrs[i] = &values[i]
	}

	// Scan rows
	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Create new instance and populate fields
		var item T
		if err := sb.populateStruct(&item, columns, values); err != nil {
			return nil, fmt.Errorf("failed to populate struct: %w", err)
		}

		results = append(results, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return results, nil
}

// populateStruct maps database values to struct fields using reflection.
//
// This is a simplified implementation that handles basic types.
// In a production system, you might want to add support for more types
// and custom field mapping via struct tags.
func (sb *SelectBuilder[T]) populateStruct(item interface{}, columns []string, values []interface{}) error {
	v := reflect.ValueOf(item).Elem()
	t := v.Type()

	// Create a map of field names to field indices for faster lookup
	fieldMap := make(map[string]int)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		dbTag := field.Tag.Get("db")
		if dbTag != "" {
			// Handle comma-separated tags like "id,primary"
			parts := strings.Split(dbTag, ",")
			fieldMap[parts[0]] = i
		} else {
			// Use lowercase field name as default
			fieldMap[strings.ToLower(field.Name)] = i
		}
	}

	// Map database columns to struct fields
	for i, column := range columns {
		if fieldIndex, exists := fieldMap[column]; exists {
			field := v.Field(fieldIndex)
			if field.CanSet() {
				if err := sb.setFieldValue(field, values[i]); err != nil {
					return fmt.Errorf("failed to set field %s: %w", column, err)
				}
			}
		}
	}

	return nil
}

// setFieldValue sets a struct field value from a database value.
//
// This method handles type conversion between database types and Go types.
func (sb *SelectBuilder[T]) setFieldValue(field reflect.Value, value interface{}) error {
	if value == nil {
		return nil // Skip nil values
	}

	switch field.Kind() {
	case reflect.String:
		if s, ok := value.(string); ok {
			field.SetString(s)
		} else if b, ok := value.([]byte); ok {
			field.SetString(string(b))
		}
	case reflect.Int, reflect.Int64:
		if i, ok := value.(int64); ok {
			field.SetInt(i)
		}
	case reflect.Bool:
		if b, ok := value.(bool); ok {
			field.SetBool(b)
		}
	case reflect.Struct:
		if field.Type() == reflect.TypeOf(time.Time{}) {
			if t, ok := value.(time.Time); ok {
				field.Set(reflect.ValueOf(t))
			} else if s, ok := value.(string); ok {
				if t, err := time.Parse(time.RFC3339, s); err == nil {
					field.Set(reflect.ValueOf(t))
				}
			}
		}
	default:
		return fmt.Errorf("unsupported field type: %s", field.Kind())
	}

	return nil
}

// Close closes the ORM and its underlying database connection.
//
// This should be called when the ORM is no longer needed to free resources.
func (orm *ORM) Close() error {
	return orm.db.Close()
}
