package DB

import (
	"github.com/xormplus/xorm"
)

type baseDao struct {
	where     string
	sql       string
	autoClose bool
	session   *xorm.Session
}

func validTx(session *xorm.Session) {
	if session == nil {
		panic("开启事务处理中session不能为空！")
	}
}

// =========请不要在此文件随意扩展方法，有需求可以提出来======================

func SQL(query string, args ...interface{}) *baseDao {
	session := Engine.NewSession()
	defer session.Close()

	dao := baseDao{session: session}
	dao.sql = query
	dao.autoClose = true
	dao.session.SQL(query, args...)
	return &dao
}

func SQL_Tx(session *xorm.Session, query string, args ...interface{}) *baseDao {
	dao := baseDao{session: session}
	dao.sql = query
	dao.autoClose = false
	dao.session.SQL(query, args...)
	return &dao
}

func (dao baseDao) validSession() {
	if dao.session == nil {
		panic("session不存在，请先调用Where或SQL函数")
	}
}

func Where(query string, args ...interface{}) *baseDao {
	session := Engine.NewSession()
	dao := baseDao{session: session}
	dao.where = query
	dao.autoClose = true
	dao.session.Where(query, args...)
	return &dao
}

func Limit(offset, limit int) *baseDao {
	session := Engine.NewSession()
	dao := baseDao{session: session}
	dao.autoClose = true
	dao.session.Limit(limit, offset)
	return &dao
}

func Count(bean interface{}) (count int64, err error) {
	session := Engine.NewSession()
	dao := baseDao{session: session}
	dao.autoClose = true
	count, err = dao.session.Count(bean)
	return
}

func WhereTx(session *xorm.Session, query string, args ...interface{}) *baseDao {
	dao := baseDao{session: session}
	dao.where = query
	dao.autoClose = false
	dao.session.Where(query, args...)
	return &dao
}

func (dao *baseDao) Where(query string, args ...interface{}) *baseDao {
	dao.where = query
	dao.session.Where(query, args...)
	return dao
}

func (dao *baseDao) Count(bean interface{}) (int64, error) {
	dao.validSession()
	if dao.autoClose {
		defer dao.session.Close()
	}

	return dao.session.Count(bean)
}

func (dao *baseDao) Cols(columns ...string) *baseDao {
	dao.validSession()
	dao.session.Cols(columns...)
	return dao
}

func (dao *baseDao) Omit(columns ...string) *baseDao {
	dao.validSession()
	dao.session.Omit(columns...)
	return dao
}

func (dao *baseDao) Limit(limit, start int) *baseDao {
	dao.validSession()
	dao.session.Limit(limit, start)
	return dao
}

func (dao *baseDao) Asc(colNames ...string) *baseDao {
	dao.validSession()
	dao.session.Asc(colNames...)
	return dao
}

func (dao *baseDao) Desc(colNames ...string) *baseDao {
	dao.validSession()
	dao.session.Desc(colNames...)
	return dao
}

func (dao *baseDao) Find(rowsSlicePtr interface{}) error {
	dao.validSession()
	if dao.autoClose {
		defer dao.session.Close()
	}

	return dao.session.Find(rowsSlicePtr)
}

func (dao *baseDao) Update(id int64, bean interface{}) (int64, error) {
	dao.validSession()
	if dao.autoClose {
		defer dao.session.Close()
	}

	if dao.where == "" {
		panic("修改条件不能为空，危险操作！")
	}

	return dao.session.ID(id).Update(bean)
}

func (dao *baseDao) Get(bean interface{}) (bool, error) {
	dao.validSession()
	if dao.autoClose {
		defer dao.session.Close()
	}

	return dao.session.Get(bean)
}

func (dao *baseDao) Delete(bean interface{}) (int64, error) {
	dao.validSession()
	if dao.autoClose {
		defer dao.session.Close()
	}

	if dao.where == "" {
		panic("删除条件不能为空，危险操作！")
	}

	return dao.session.Delete(bean)
}

func GetById(id int64, bean interface{}) (bool, error) {
	return Engine.ID(id).Get(bean)
}

func FindByIdTx(id int64, bean interface{}, session *xorm.Session) (bool, error) {
	validTx(session)
	return session.ID(id).Get(bean)
}

func Find(rowsSlicePtr interface{}, limit, start int) error {
	return Engine.Limit(limit, start).Find(rowsSlicePtr)
}

func Find_Tx(rowsSlicePtr interface{}, limit, start int, session *xorm.Session) error {
	validTx(session)
	return session.Limit(limit, start).Find(rowsSlicePtr)
}

func FindBySQL(sql string, rowsSlicePtr interface{}) error {
	return Engine.SQL(sql).Find(rowsSlicePtr)
}

func FindBySQL_Tx(sql string, rowsSlicePtr interface{}, session *xorm.Session) error {
	validTx(session)
	return session.SQL(sql).Find(rowsSlicePtr)
}

func FindBySQL_V2(sql string, args *map[string]interface{}, rowsSlicePtr interface{}, session *xorm.Session) error {
	if session == nil {
		session = Engine.NewSession()
		defer session.Close()
	}

	return session.SQL(sql, args).Find(rowsSlicePtr)
}

func GetBySQL(bean interface{}, sql string, args ...interface{}) (bool, error) {
	return Engine.SQL(sql, args...).Get(bean)
}

func GetBySQL_Tx(session *xorm.Session, bean interface{}, sql string, args ...interface{}) (bool, error) {
	validTx(session)
	return session.SQL(sql).Get(bean)
}

func GetBySQLV2(sql string, args *map[string]interface{}, bean interface{}, session *xorm.Session) (bool, error) {
	return Engine.SQL(sql, args).Get(bean)
}

func GetBySQLV2_Tx(sql string, args *map[string]interface{}, bean interface{}, session *xorm.Session) (bool, error) {
	validTx(session)
	return session.SQL(sql, args).Get(bean)
}

func FindBySqlTemplate(sqlTemplateName string, args *map[string]interface{}, rowsSlicePtr interface{}) error {
	return Engine.SqlTemplateClient(sqlTemplateName, args).Find(rowsSlicePtr)
}

func FindBySqlTemplateTx(sqlTemplateName string, args *map[string]interface{}, rowsSlicePtr interface{}, session *xorm.Session) error {
	validTx(session)
	return session.SqlTemplateClient(sqlTemplateName, args).Find(rowsSlicePtr)
}

func GetBySqlTemplate(sqlTemplateName string, args *map[string]interface{}, bean interface{}) (bool, error) {
	return Engine.SqlTemplateClient(sqlTemplateName, args).Get(bean)
}

func GetBySqlTemplateTx(sqlTemplateName string, args *map[string]interface{}, bean interface{}, session *xorm.Session) (bool, error) {
	validTx(session)
	return session.SqlTemplateClient(sqlTemplateName, args).Get(bean)
}

func Insert(bean interface{}) (int64, error) {
	return Engine.Insert(bean)
}

func InsertTx(session *xorm.Session, beans ...interface{}) (int64, error) {
	return session.Insert(beans...)
}

func InsertBatchTx(session *xorm.Session, rowsSlicePtr interface{}) (int64, error) {
	validTx(session)
	return session.InsertMulti(rowsSlicePtr)
}

func InsertBatch(rowsSlicePtr interface{}) (int64, error) {
	session := Engine.NewSession()
	defer session.Close()

	return session.InsertMulti(rowsSlicePtr)
}

func UpdateById(id int64, bean interface{}) (int64, error) {
	return Engine.ID(id).Update(bean)
}

func UpdateByIdTx(session *xorm.Session, id int64, bean interface{}) (int64, error) {
	validTx(session)
	return session.ID(id).Update(bean)
}

func UpdateByIdWithOmit(id int64, bean interface{}, omitColumns ...string) (int64, error) {
	return Engine.ID(id).Omit(omitColumns...).Update(bean)
}

func UpdateByIdWithOmitTx(session *xorm.Session, id int64, bean interface{}, omitColumns ...string) (int64, error) {
	validTx(session)
	return session.ID(id).Omit(omitColumns...).Update(bean)
}

func UpdateByIdWithColumns(id int64, bean interface{}, updateColumns ...string) (int64, error) {
	return Engine.ID(id).Cols().Cols(updateColumns...).Update(bean)
}

func UpdateByIdWithMustColumns(id int64, bean interface{}, mustColumns ...string) (int64, error) {
	return Engine.ID(id).MustCols(mustColumns...).Update(bean)
}

func UpdateByIdWithColumnsTx(session *xorm.Session, id int64, bean interface{}, updateColumns ...string) (int64, error) {
	validTx(session)
	return session.ID(id).Cols().Cols(updateColumns...).Update(bean)
}

func DeleteById(id int64, bean interface{}) (int64, error) {
	return Engine.ID(id).Delete(bean)
}

func DeleteByIdTx(id int64, bean interface{}, session *xorm.Session) (int64, error) {
	validTx(session)
	return session.ID(id).Delete(bean)
}

func ExecuteSQL(sqlorArgs ...interface{}) error {
	_, err := Engine.Exec(sqlorArgs...)
	return err
}

func ExecuteSQLTx(session *xorm.Session, sqlorArgs ...interface{}) error {
	_, err := session.Exec(sqlorArgs...)
	return err
}

// stpl分页查询
func PageBySqlTemplateClient(datasStpl string, args *map[string]interface{}, datas interface{}, totalStpl string, total interface{}) (err error) {
	if err = Engine.SqlTemplateClient(datasStpl, args).Find(datas); err != nil {
		return
	}

	_, err = Engine.SqlTemplateClient(totalStpl, args).Get(total)
	return
}

func CountBySqlTemplate(totalStpl string, args *map[string]interface{}, total interface{}) (err error) {
	_, err = Engine.SqlTemplateClient(totalStpl, args).Get(total)
	return
}

// =========请不要在此文件随意扩展方法，有需求可以提出来======================
