package dto

type Pages struct {
	Total int64
	Data  interface{}
}

func NewPages(total int64, data interface{}) *Pages {
	return &Pages{Total: total, Data: data}
}
