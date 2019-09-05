package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var UserCounter int
var UserArray []User
var UserTokenMapID = make(map[string]int)
var UsernameMapID = make(map[string]int)
var EmailMapID = make(map[string]int)

type User struct {
	ID       int
	Username string
	Password string
	Email    string
	Avatar   string
	Token    string
}

type ErrorResponse struct {
	Error   int    `json:"error"`
	Message string `json:"message"`
}

const (
	InvalidForm = iota
	InvalidUsername
	InvalidPassword
	InvalidEmail
	UsernameExist
	EmailExist
	InvalidUsernameOrPassword
	InvalidAvatar
)

type RegisterResponse struct {
	ID    int    `json:"id"`
	Token string `json:"token"`
}

type LoginResponse struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Token    string `json:"token"`
}

func validate(text, reg string) (string, bool) {
	r := regexp.MustCompile("^" + reg + "$")
	return text, r.MatchString(text)
}

func newToken() string {
	b := make([]byte, 32)
	binary.BigEndian.PutUint64(b[0:8], uint64(time.Now().UnixNano()))
	binary.BigEndian.PutUint64(b[8:16], rand.Uint64())
	binary.BigEndian.PutUint64(b[16:24], rand.Uint64())
	binary.BigEndian.PutUint64(b[24:32], rand.Uint64())
	return strings.ToUpper(hex.EncodeToString(b))
}

var TokenMutex sync.Mutex

func resetAccessToken(ID int, oldToken string) string {
	TokenMutex.Lock()
	defer TokenMutex.Unlock()
	if oldToken != "" {
		delete(UserTokenMapID, oldToken)
	}
	for {
		token := newToken()
		if _, ok := UserTokenMapID[token]; !ok {
			UserTokenMapID[token] = ID
			return token
		}
	}
}

func getIDFromToken(token string) (int, bool) {
	TokenMutex.Lock()
	defer TokenMutex.Unlock()
	ID, ok := UserTokenMapID[token]
	return ID, ok
}

func webReturnError(w http.ResponseWriter, errorCode int) {
	var m string
	switch errorCode {
	case InvalidForm:
		m = "错误的表单"
	case InvalidUsername:
		m = "用户名必须是大小写字母、数字与下划线，长度在3到20之间"
	case InvalidPassword:
		m = "密码必须为可见字符，长度在6到30之间"
	case InvalidEmail:
		m = "邮箱格式不合法或者长度超过了100"
	case UsernameExist:
		m = "此用户名已被注册"
	case EmailExist:
		m = "此邮箱已被注册"
	case InvalidUsernameOrPassword:
		m = "用户名或密码错误"
	case InvalidAvatar:
		m = "头像链接不合法或长度超过了200"
	default:
		m = "未知错误"
	}
	json.NewEncoder(w).Encode(ErrorResponse{errorCode, m})
}

func checkForm(w http.ResponseWriter, r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		log.Println(err)
		webReturnError(w, InvalidForm)
		return false
	}
	return true
}

var RegisterMutex sync.Mutex

func webRegister(w http.ResponseWriter, r *http.Request) {
	if !checkForm(w, r) {
		return
	}
	username, ok := validate(r.Form.Get("username"), `[a-zA-Z0-9_]{3,20}`)
	if !ok {
		webReturnError(w, InvalidUsername)
		return
	}
	password, ok := validate(r.Form.Get("password"), `\S{6,30}`)
	if !ok {
		webReturnError(w, InvalidPassword)
		return
	}
	email, ok := validate(r.Form.Get("email"), `[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+`)
	if !ok || len(email) > 100 {
		webReturnError(w, InvalidEmail)
		return
	}
	avatar, ok := validate(r.Form.Get("avatar"), `\S{0,200}`)
	if !ok {
		webReturnError(w, InvalidAvatar)
		return
	}
	if _, ok = UsernameMapID[username]; ok {
		webReturnError(w, UsernameExist)
		return
	}
	if _, ok = EmailMapID[email]; ok {
		webReturnError(w, EmailExist)
		return
	}
	RegisterMutex.Lock()
	defer RegisterMutex.Unlock()
	password = fmt.Sprintf("%x", sha256.Sum256([]byte("gggg"+password+"mf")))
	ID := len(UserArray)
	token := resetAccessToken(ID, "")
	user := User{ID, username, password, email, token, avatar}
	UserArray = append(UserArray, user)
	UsernameMapID[username] = ID
	EmailMapID[email] = ID
	json.NewEncoder(w).Encode(RegisterResponse{ID, token})
}

func webLogin(w http.ResponseWriter, r *http.Request) {
	if !checkForm(w, r) {
		return
	}
	username := r.Form.Get("username")
	password := fmt.Sprintf("%x", sha256.Sum256([]byte("gggg"+r.Form.Get("password")+"mf")))
	if ID, ok := UsernameMapID[username]; ok {
		user := UserArray[ID]
		if user.Password == password {
			user.Token = resetAccessToken(ID, user.Token)
			json.NewEncoder(w).Encode(LoginResponse{ID, user.Username, user.Email, user.Token})
			return
		}
	}
	webReturnError(w, InvalidUsernameOrPassword)
}

func webEdit(w http.ResponseWriter, r *http.Request) {
	if !checkForm(w, r) {
		return
	}
	token := r.Form.Get("token")
	avatar, ok := validate(r.Form.Get("avatar"), `\S{0,200}`)
	if !ok {
		webReturnError(w, InvalidAvatar)
		return
	}
	if ID, ok := getIDFromToken(token); ok {
		user := UserArray[ID]
		user.Avatar = avatar
		fmt.Fprintf(w, "{}")
		return
	}
	webReturnError(w, InvalidUsernameOrPassword)
}

func main() {
	http.HandleFunc("/register", webRegister)
	http.HandleFunc("/login", webLogin)
	http.HandleFunc("/edit", webEdit)
	log.Fatal(http.ListenAndServe(":18888", nil))
}