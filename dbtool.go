package dbtool

import (
	"crypto/rsa"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/docculi-company/awso"
	"github.com/go-redis/redis"
	"github.com/lithammer/shortuuid/v3"
	"golang.org/x/crypto/bcrypt"
)

//
//
// Query
//
//
func Query(tx *sql.Tx, query string, params []interface{}, cols []string) ([]interface{}, error) {
	var resRows []interface{}
	rowBuf := make([]interface{}, len(cols))

	rows, err := tx.Query(query, params...)
	if err != nil {
		return nil, err
	} else {
		defer rows.Close()
		for rows.Next() {
			// allocate new map for each row result
			rowMap := make(map[string]interface{})

			// create/renew pointers for each row scan
			for i := range rowBuf {
				rowBuf[i] = new(interface{})
			}

			err = rows.Scan(rowBuf...)
			if err != nil {
				return nil, err
			} else {
				for i := range rowBuf {
					rowMap[cols[i]] = *rowBuf[i].(*interface{})

					s := fmt.Sprintf("%v", rowMap[cols[i]])

					// check for map and decode
					_, err := hex.DecodeString(s)
					if err == nil {
						m, err := DecodeStringToMSI(s)
						if err == nil {
							rowMap[cols[i]] = m
						} else {
							a, err := DecodeStringToAr(s)
							if err == nil {
								rowMap[cols[i]] = a
							}
						}
					}

					// have to replace % to avoid ! (MISSING)
					if strings.ContainsAny(s, "%") {
						rowMap[cols[i]] = strings.ReplaceAll(s, "%", "&percnt;")
					}
				}
				resRows = append(resRows, rowMap)
			}
		}
	}

	return resRows, nil
}

//
//
// ArrayToMap
//
//
func ArrayToMap(ar []interface{}, attribute string) (map[string]interface{}, error) {
	retMap := make(map[string]interface{})
	for i := range ar {
		elementMap := ar[i].(map[string]interface{})
		indexInterface, b := elementMap[attribute]
		if !b {
			err := fmt.Errorf("dbtool error: could not find map key")
			return nil, err
		}
		index := fmt.Sprintf("%v", indexInterface)
		retMap[index] = ar[i]
	}
	return retMap, nil
}

//
//
// QueryToMap
//
//
func QueryToMap(tx *sql.Tx, query string, params []interface{}, attribute string, cols []string) (map[string]interface{}, error) {
	ar, err := Query(tx, query, params, cols)
	if err != nil {
		return nil, err
	} else {
		retMap, err := ArrayToMap(ar, attribute)
		if err != nil {
			return nil, err
		} else {
			return retMap, nil
		}
	}
}

//
//
// contains (for QueryWithFile)
//
//
func contains(ar []string, s string) (int, bool) {
	for i, e := range ar {
		if e == s {
			return i, true
		}
	}
	return -1, false
}

//
//
// QueryWithFile
//
//
func QueryWithFile(awso *awso.Awso, tx *sql.Tx, query string, params []interface{}, cols []string, signedUrlIds []string, fileCols []string) ([]interface{}, error) {
	var resRows []interface{}
	rowBuf := make([]interface{}, len(cols))

	rows, err := tx.Query(query, params...)
	if err != nil {
		return nil, err
	} else {
		defer rows.Close()
		for rows.Next() {
			// allocate new map for each row result
			rowMap := make(map[string]interface{})

			// create/renew pointers for each row scan
			for i := range rowBuf {
				rowBuf[i] = new(interface{})
			}

			err = rows.Scan(rowBuf...)
			if err != nil {
				return nil, err
			} else {
				for i := range rowBuf {
					rowMap[cols[i]] = *rowBuf[i].(*interface{})

					// signed url creation
					j, b := contains(fileCols, cols[i])
					if b && (j > -1) {
						rowMap[cols[i]] = awso.GetSignedUrl(fmt.Sprintf("%v", rowMap[signedUrlIds[j]]), fmt.Sprintf("%v", rowMap[cols[i]]))
					}

					s := fmt.Sprintf("%v", rowMap[cols[i]])

					// check for map and decode
					_, err := hex.DecodeString(s)
					if err == nil {
						m, err := DecodeStringToMSI(s)
						if err == nil {
							rowMap[cols[i]] = m
						} else {
							a, err := DecodeStringToAr(s)
							if err == nil {
								rowMap[cols[i]] = a
							}
						}
					}

					// have to replace % to avoid ! (MISSING)
					if strings.ContainsAny(s, "%") {
						rowMap[cols[i]] = strings.ReplaceAll(s, "%", "&percnt;")
					}
				}
				resRows = append(resRows, rowMap)
			}
		}
	}

	return resRows, nil
}

//
//
// QueryToMapWithFile
//
//
func QueryToMapWithFile(awso *awso.Awso, tx *sql.Tx, query string, params []interface{}, attribute string, cols []string, signedUrlIds []string, fileCols []string) (map[string]interface{}, error) {
	ar, err := QueryWithFile(awso, tx, query, params, cols, signedUrlIds, fileCols)
	if err != nil {
		return nil, err
	} else {
		retMap, err := ArrayToMap(ar, attribute)
		if err != nil {
			return nil, err
		} else {
			return retMap, nil
		}
	}
}

//
//
// Hashes a password with a salt
//
//
func HashWithSalt(pwd string) (string, error) {
	bytePwd := []byte(pwd)
	hash, err := bcrypt.GenerateFromPassword(bytePwd, bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

//
//
// Compares hashed password with regular text password
//
//
func CmpPwd(hashPwd string, pwd string) (bool, error) {
	byteHashPwd := []byte(hashPwd)
	bytePwd := []byte(pwd)
	err := bcrypt.CompareHashAndPassword(byteHashPwd, bytePwd)
	if err != nil {
		return false, err
	}
	return true, nil
}

//
//
// Creates a JWT and stores it in the redis cache
//
//
func CreateAndStoreJwt(usrId string /*ip string,*/, signKey *rsa.PrivateKey, redisClient *redis.Client, hour time.Duration) (string, error) {
	// create JWT key
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"usrId": usrId /*"ip": ip*/})
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		return "", err
	}
	// create usrId value (ip also?)
	tokenMap := make(map[string]interface{})
	tokenMap["usrId"] = usrId
	//tokenMap["ip"] = ip
	tData, err := json.Marshal(tokenMap)
	if err != nil {
		return "", err
	}
	// May have to use string instead of tData ([]byte)
	err = redisClient.Set(tokenString, tData, hour*time.Hour).Err()
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

//
//
// Creates a JWT and stores it in the redis cache
//
//
func CreateAndStoreShortUuid(usrId string /*ip string,*/, redisClient *redis.Client, hour time.Duration) (string, error) {
	key := shortuuid.New()
	tokenMap := make(map[string]interface{})
	tokenMap["usrId"] = usrId
	//tokenMap["ip"] = ip
	tData, err := json.Marshal(tokenMap)
	if err != nil {
		return "", err
	}
	// May have to use string instead of tData ([]byte)
	err = redisClient.Set(key, tData, hour*time.Hour).Err()
	if err != nil {
		return "", err
	}
	return key, nil
}

//
//
// Get private key to sign JWT
//
//
func GetSignKey(path string) (*rsa.PrivateKey, error) {
	signBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return nil, err
	}
	return signKey, nil
}

//
//
// Get public key to verify JWT
//
//
func GetVerifyKey(path string) (*rsa.PublicKey, error) {
	verifyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return nil, err
	}
	return verifyKey, nil
}

//
//
// Return correct formatting of domain name on test vs. live
//
//
func GetOriginDomain() string {
	if strings.Contains(os.Getenv("ORIGIN_DOMAIN"), "localhost") {
		return `http://` + os.Getenv("ORIGIN_DOMAIN")
	}
	return `https://www.` + os.Getenv("ORIGIN_DOMAIN")
}

//
//
// Encode map-string-interface to a byte string
//
//
func EncodeMSIToString(m map[string]interface{}) (string, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

//
//
// Encode map-string-interface to a byte string
//
//
func DecodeStringToMSI(s string) (map[string]interface{}, error) {
	b, err := hex.DecodeString(s)

	var m map[string]interface{}
	err = json.Unmarshal(b, &m)
	if err != nil {
		return make(map[string]interface{}), err
	}

	return m, nil
}

//
//
// Encode map-string-interface to a byte string
//
//
func EncodeArToString(a []interface{}) (string, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

//
//
// Encode map-string-interface to a byte string
//
//
func DecodeStringToAr(s string) ([]interface{}, error) {
	b, err := hex.DecodeString(s)

	var a []interface{}
	err = json.Unmarshal(b, &a)
	if err != nil {
		return make([]interface{}, 0, 8), err
	}

	return a, nil
}

//
//
// Check authentication
//
//
func VerifyAuth(rc *redis.Client, authToken string, usrId string /*ip string,*/, topic string, noAuthTopics map[string]bool) error {
	if noAuthTopics[topic] {
		return nil
	} else if usrId == "" {
		err := fmt.Errorf("no user id supplied")
		return err
	} else if authToken == "" {
		err := fmt.Errorf("no authentication token supplied")
		return err
		/*else if ip == "" {
			err := fmt.Errorf("no ip supplied")
			return err
		}*/
	} else {
		err := VerifyToken(rc, authToken, usrId /*, ip*/)
		if err != nil {
			return err
		}
	}
	return nil
}

//
//
// Verify token with redis store
//
//
func VerifyToken(rc *redis.Client, authToken string, usrId string /*, ip string*/) error {
	token, err := rc.Get(authToken).Result()
	if err == redis.Nil {
		return err
	} else if err != nil {
		return err
	}
	var tokenMap map[string]interface{}
	err = json.Unmarshal([]byte(token), &tokenMap)
	if err != nil {
		return err
	} else if fmt.Sprintf("%v", tokenMap["usrId"]) != usrId {
		return fmt.Errorf("auth token usrId '%v' does not match %v", tokenMap["usrId"], usrId)
	} /*else if fmt.Sprintf("%v", tokenMap["ip"]) != ip {
		return fmt.Errorf("auth token ip '%v' does not match %v", tokenMap["ip"], ip)
	}*/
	return nil
}

//
//
// Compile SQL 'in-clause' from a result set from dbtool.Query (removes duplicates)
//
//
func InFromResult(res *[]interface{}, idType string) string {
	uids := UidsFromResult(res, idType)
	in := ""
	for i, v := range uids {
		in += "'" + v + "'"
		if i < len(uids)-1 {
			in += ", "
		}
	}
	return in
}

//
//
// Pull uids from a result set from dbtool.Query (removes duplicates)
//
//
func UidsFromResult(res *[]interface{}, idType string) []string {
	var uids []string
	k := make(map[string]bool)
	for _, value := range *res {
		v := value.(map[string]interface{})
		if _, ok := v[idType]; ok {
			id := fmt.Sprintf("%v", v[idType])
			if _, v2 := k[id]; !v2 {
				k[id] = true
				uids = append(uids, id)
			}
		}
	}
	return uids
}

//
//
// HtmlTableBegin
//
//
func HtmlTableBegin() string {
	return `<table align="center" width="600" cellspacing="0" cellpadding="0" border="0" style="border-collapse: collapse;">`
}

//
//
// HtmlTableEnd
//
//
func HtmlTableEnd() string {
	return `</table>`
}

//
//
// HtmlTrUnsubEnId
//
//
func HtmlTrUnsubEnId(email string, emailNoteId string) string {
	return `
		<tr>
			<td>
				<div style="font-size: 12px; margin-bottom: 16px;">
					This message was sent to <a href="mailto:` + email + `" style="text-decoration: none;">` + email + `</a>. 
					If you don't want to receive these emails from Docculi in the future, please 
					<a href="` + GetOriginDomain() + `/#/unsubscribe/0/` + emailNoteId + `" style="text-decoration: none;">unsubscribe</a>.
				</div>
				<div style="font-size: 12px;">
					&copy; 2021 Docculi, LLC., 215 South Denton Tap Road Suite 275, Coppell TX 75019. 
				</div>
			</td>
		</tr>
	`
}

//
//
// HtmlTrUnsubEmail
//
//
func HtmlTrUnsubEmail(email string) string {
	return `
		<tr>
			<td>
				<div style="font-size: 12px; margin-bottom: 16px;">
					This message was sent to <a href="mailto:` + email + `" style="text-decoration: none;">` + email + `</a>. 
					If you don't want to receive these emails from Docculi in the future, please 
					<a href="` + GetOriginDomain() + `/#/unsubscribe/0/` + email + `" style="text-decoration: none;">unsubscribe</a>.
				</div>
				<div style="font-size: 12px; margin-bottom: 16px;">
					This is an advertisement from Docculi, LLC.
				</div>
				<div style="font-size: 12px;">
					&copy; 2021 Docculi, LLC., 215 South Denton Tap Road Suite 275, Coppell TX 75019.
				</div>
			</td>
		</tr>
	`
}
