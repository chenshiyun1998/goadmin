package sys

type Org struct {
	Id       int64  `json:"id"`
	ParentId int64  `json:"parent_id"`
	Name     string `json:"name"`
	Code     string `json:"code"`
}
