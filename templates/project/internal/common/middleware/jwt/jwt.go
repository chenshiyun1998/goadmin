/**
 * Created by Wangwei on 2019-06-06 10:52.
 */

package jwt

import (
	"errors"
	"goprojects/internal/common"
	"goprojects/internal/conf"
	"time"

	JwtGo "github.com/dgrijalva/jwt-go"

	"strings"
)

//JWT签名结构
type JWT struct {
	JwtSecret []byte
}

var (
	TokenExpired     = errors.New("Token is expired")
	TokenNotValidYet = errors.New("Token not active yet")
	TokenMalformed   = errors.New("That's not even a token")
	TokenInvalid     = errors.New("Token invalid!")
)

type EmployeeClaims struct {
	EmployeeId int64  `json:"employee_id"` //员工或用户id
	Account    string `json:"account"`     //员工或用户账号
	RoleId     int64  `json:"role_id"`     //员工角色
	OrgTypeId  int64  `json:"org_type_id"` //机构类型id
	OrgId      int64  `json:"org_id"`      //机构id
	OrgName    string `json:"org_name"`    //机构名称
	ClientId   string `json:"client_id"`   //客户端id
	JwtGo.StandardClaims
}

// 这里的用户指的是小程序，h5等用户
type UserClaims struct {
	UserId    int64  `json:"user_id"`     //用户ID
	OpenId    string `json:"open_id"`     //开放平台ID
	Name      string `json:"name"`        //用户姓名
	OrgTypeId int64  `json:"org_type_id"` //机构类型id
	OrgId     int64  `json:"org_id"`      //机构id
	OrgName   string `json:"org_name"`    //机构名称
	ClientId  string `json:"client_id"`   //客户端id
	JwtGo.StandardClaims
}

func (jwt *JWT) getJwtSecret() []byte {
	if len(jwt.JwtSecret) == 0 {
		jwt.JwtSecret = []byte(conf.AppConf.JwtSecret)
	}

	return jwt.JwtSecret
}

// 生成员工token
func (jwt *JWT) GenEmployeeToken(userId int64, account string, roleId, orgTypeId, orgId int64, orgName, clientId string) (string, int64, error) {
	clientId = common.FormatClientId(clientId)
	exp := GetExp(clientId)
	claims := EmployeeClaims{
		EmployeeId: userId,
		Account:    account,
		ClientId:   clientId,
		RoleId:     roleId,
		OrgTypeId:  orgTypeId,
		OrgId:      orgId,
		OrgName:    orgName,
		StandardClaims: JwtGo.StandardClaims{
			ExpiresAt: exp.Unix(),
			Issuer:    "",
		},
	}

	token := JwtGo.NewWithClaims(JwtGo.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(jwt.getJwtSecret())
	if err != nil {
		return "", 0, err
	}

	return tokenStr, exp.Unix(), nil
}

// 将员工token解密
func (jwt *JWT) ParseEmployeeToken(tokenStr string) (*EmployeeClaims, error) {
	token, err := JwtGo.ParseWithClaims(tokenStr, &EmployeeClaims{}, func(token *JwtGo.Token) (interface{}, error) {
		return jwt.JwtSecret, nil
	})

	if err != nil {
		if ve, ok := err.(*JwtGo.ValidationError); ok {
			if ve.Errors&JwtGo.ValidationErrorMalformed != 0 {
				return nil, TokenMalformed
			} else if ve.Errors&JwtGo.ValidationErrorExpired != 0 {
				return nil, TokenExpired
			} else if ve.Errors&JwtGo.ValidationErrorNotValidYet != 0 {
				return nil, TokenNotValidYet
			} else {
				return nil, TokenInvalid
			}
		}
	}

	if claims, ok := token.Claims.(*EmployeeClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, err
}

// 生成用户token
func (jwt *JWT) GenH5UserToken(userId int64, openId, name string, orgTypeId, orgId int64, orgName, clientId string) (string, int64, error) {
	clientId = common.FormatClientId(clientId)
	exp := GetExp(clientId)
	claims := UserClaims{
		UserId:    userId,
		OpenId:    openId,
		Name:      name,
		ClientId:  clientId,
		OrgTypeId: orgTypeId,
		OrgId:     orgId,
		OrgName:   orgName,
		StandardClaims: JwtGo.StandardClaims{
			ExpiresAt: exp.Unix(),
			Issuer:    "",
		},
	}

	token := JwtGo.NewWithClaims(JwtGo.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(jwt.getJwtSecret())
	if err != nil {
		return "", 0, err
	}

	return tokenStr, exp.Unix(), nil
}

// 将用户token解密
func (jwt *JWT) ParseUserToken(tokenStr string) (*UserClaims, error) {
	token, err := JwtGo.ParseWithClaims(tokenStr, &UserClaims{}, func(token *JwtGo.Token) (interface{}, error) {
		return jwt.JwtSecret, nil
	})

	if err != nil {
		if ve, ok := err.(*JwtGo.ValidationError); ok {
			if ve.Errors&JwtGo.ValidationErrorMalformed != 0 {
				return nil, TokenMalformed
			} else if ve.Errors&JwtGo.ValidationErrorExpired != 0 {
				return nil, TokenExpired
			} else if ve.Errors&JwtGo.ValidationErrorNotValidYet != 0 {
				return nil, TokenNotValidYet
			} else {
				return nil, TokenInvalid
			}
		}
	}

	if claims, ok := token.Claims.(*UserClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, err
}

// 设置token的有效期时间
func GetExp(clientId string) time.Time {
	var exp time.Time
	now := time.Now()
	if strings.HasPrefix(clientId, "webadmin") {
		exp = now.Add(30 * 24 * time.Hour)
	} else if strings.ContainsAny(clientId, "pc") {
		exp = now.Add(365 * 10 * 24 * time.Hour)
	} else if strings.HasPrefix(clientId, "app") {
		exp = now.Add(365 * 10 * 24 * time.Hour)
		//exp = now.AddDate(0,0,365)
	} else if strings.HasPrefix(clientId, "h5") {
		exp = now.Add(30 * 24 * time.Hour)
		//exp = now.AddDate(0,0,365)
	} else {
		exp = now.Add(30 * 24 * time.Hour)
	}

	return exp
}
