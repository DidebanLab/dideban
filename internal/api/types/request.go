package types

// PaginationRequest represents pagination parameters in requests.
//
// When the "short" parameter is present and true, the API returns a compact
// representation containing only [id, is_offline] for each record, with a
// default page_size of 500 (overriding the normal default of 50).
type PaginationRequest struct {
	Page     int  `form:"page,default=1" binding:"min=1"`
	PageSize int  `form:"page_size,default=50" binding:"min=1,max=500"`
	Short    bool `form:"short,default=false"`
}
