/**
 * Created by Wangwei on 2019-03-22 10:11.
 */

package state

const (
	Success                     = 0                  // 成功
	UnknownError                = iota + 100000      // 未知错误，从1 + 100000开始枚举
	ServerError                                      // 服务内部错误
	ReqParamEmpty                                    // 请求参数为空
	ReqParamError                                    // 请求参数错误
	DbConnException                                  // 数据库连接异常
	DbExecSqlException                               // 数据库执行SQL异常
	RedisConnException                               // Redis连接异常
	RedisOpException                                 // Redis操作异常
	DataDuplication                                  // 数据重复
	NoExpectData                                     // 无符合要求的数据
	OperateFail                                      // 操作失败
	ApiPermissionDenied                              // 接口权限不足
	ReportDataSyncTypeError     = (iota + 3) + 10000 // 上报数据的同步类型错误，中间跳过3个连续编码，所以加iota + 3
	ReportDataCompressTypeError                      // 上报数据的压缩类型错误
	ReportDataJSONError                              // 上报数据的data的JSON格式错误
	ReportDataEmpty                                  // 上报数据体为空
	SignError                                        // 签名错误
)

func Message(code int) string {
	switch code {
	case UnknownError:
		return "未知错误"
	case ServerError:
		return "服务内部错误"
	case ReqParamEmpty:
		return "请求参数为空"
	case ReqParamError:
		return "请求参数错误"
	case DataDuplication:
		return "数据重复"
	case NoExpectData:
		return "无符合要求的数据"
	case ApiPermissionDenied:
		return "接口权限不足"
	case ReportDataSyncTypeError:
		return "上报数据的同步类型错误"
	case ReportDataJSONError:
		return "上报数据的data的JSON格式错误"
	case ReportDataEmpty:
		return "上报数据体为空"
	case SignError:
		return "签名错误"
	default:
		return ""
	}

	return ""
}

// 同时获取code和message
func CodeMessage(code int) (int, string) {
	return code, Message(code)
}
