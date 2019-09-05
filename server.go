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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ErrorResponse struct {
	Error   int    `json:"error"`
	Message string `json:"msg"`
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
	InvalidToken
	InvalidListType
	InvalidSaveList
)

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
	case InvalidToken:
		m = "无效的token"
	case InvalidListType:
		m = "类型只能是category、favorite、history之一"
	case InvalidSaveList:
		m = "保存的列表不合法"
	default:
		m = "未知错误"
	}
	json.NewEncoder(w).Encode(ErrorResponse{errorCode, m})
}

var UserArray = make([]User, 0)
var UserTokenMapID = make(map[string]int)
var UsernameMapID = make(map[string]int)
var EmailMapID = make(map[string]int)

type Item struct {
	NewsID string `json:"news_id"`
	Time   string `json:"time"`
}

type User struct {
	lock              *sync.RWMutex
	ID                int      `json:"id"`
	Username          string   `json:"username"`
	Password          string   `json:"-"`
	Email             string   `json:"email"`
	Avatar            string   `json:"avatar"`
	Token             string   `json:"token"`
	CategoryList      []string `json:"category_list"`
	SearchHistoryList []string `json:"search_history_list"`
	FavoriteList      []Item   `json:"favorite_list"`
	HistoryList       []Item   `json:"history_list"`
}

type RegisterResponse struct {
	ID    int    `json:"id"`
	Token string `json:"token"`
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

var TokenMutex sync.RWMutex

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
	TokenMutex.RLock()
	defer TokenMutex.RUnlock()
	ID, ok := UserTokenMapID[token]
	return ID, ok
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
	user := User{new(sync.RWMutex), ID, username, password, email, avatar, token, make([]string, 0), make([]string, 0), make([]Item, 0), make([]Item, 0)}
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
		user := &UserArray[ID]
		if user.Password == password {
			user.Token = resetAccessToken(ID, user.Token)
			json.NewEncoder(w).Encode(user)
			return
		}
	}
	webReturnError(w, InvalidUsernameOrPassword)
}

func webUser(w http.ResponseWriter, r *http.Request) {
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
		user := &UserArray[ID]
		user.lock.Lock()
		user.Avatar = avatar
		user.lock.Unlock()
		fmt.Fprintf(w, "{}")
		return
	}
	webReturnError(w, InvalidToken)
}

func webGetList(w http.ResponseWriter, r *http.Request) {
	if !checkForm(w, r) {
		return
	}
	token := r.Form.Get("token")
	listType, ok := validate(r.Form.Get("type"), `(category|search_history|favorite|history)`)
	if !ok {
		webReturnError(w, InvalidListType)
		return
	}
	skip := 0
	limit := -1
	if tmp, err := strconv.Atoi(r.Form.Get("skip")); err == nil && tmp >= 0 {
		skip = tmp
	}
	if tmp, err := strconv.Atoi(r.Form.Get("limit")); err == nil && tmp >= -1 {
		limit = tmp
	}
	if ID, ok := getIDFromToken(token); ok {
		user := &UserArray[ID]
		user.lock.RLock()
		defer user.lock.RUnlock()
		num := 0
		switch listType {
		case "category":
			num = len(user.CategoryList)
		case "search_history":
			num = len(user.SearchHistoryList)
		case "favorite":
			num = len(user.FavoriteList)
		case "history":
			num = len(user.HistoryList)
		}
		end := skip + limit
		if limit == -1 || end > num {
			end = num
		}
		if skip >= end {
			json.NewEncoder(w).Encode(make([]string, 0))
			return
		}
		switch listType {
		case "category":
			json.NewEncoder(w).Encode(user.CategoryList[skip:end])
		case "search_history":
			json.NewEncoder(w).Encode(user.FavoriteList[skip:end])
		case "favorite":
			json.NewEncoder(w).Encode(user.FavoriteList[skip:end])
		case "history":
			json.NewEncoder(w).Encode(user.FavoriteList[skip:end])
		}
		return
	}
	webReturnError(w, InvalidToken)
}

func webSetList(w http.ResponseWriter, r *http.Request) {
	if !checkForm(w, r) {
		return
	}
	token := r.Form.Get("token")
	listType, ok := validate(r.Form.Get("type"), `(category|search_history|favorite|history)`)
	if !ok {
		webReturnError(w, InvalidListType)
		return
	}
	var data1 []string
	var data2 []Item
	if listType == "category" || listType == "search_history" {
		if err := json.Unmarshal([]byte(r.Form.Get("data")), &data1); err != nil {
			webReturnError(w, InvalidSaveList)
			return
		}
	} else {
		if err := json.Unmarshal([]byte(r.Form.Get("data")), &data2); err != nil {
			webReturnError(w, InvalidSaveList)
			return
		}
		sort.Slice(data2, func(i, j int) bool {
			return data2[i].Time < data2[j].Time
		})
	}
	if ID, ok := getIDFromToken(token); ok {
		user := &UserArray[ID]
		user.lock.Lock()
		defer user.lock.Unlock()
		switch listType {
		case "category":
			user.CategoryList = data1
		case "search_history":
			user.SearchHistoryList = data1
		case "favorite":
			user.FavoriteList = data2
		case "history":
			user.HistoryList = data2
		}
		fmt.Fprintf(w, "{}")
		return
	}
	webReturnError(w, InvalidToken)
}

func main() {
	http.HandleFunc("/register", webRegister)
	http.HandleFunc("/login", webLogin)
	http.HandleFunc("/user", webUser)
	http.HandleFunc("/getList", webGetList)
	http.HandleFunc("/setList", webSetList)
	log.Fatal(http.ListenAndServe(":18888", nil))
}
