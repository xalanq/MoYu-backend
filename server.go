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
	InvalidSetList
	InvalidAddList
	InvalidDelList
	InvalidNews
	InvalidNewsList
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
	case InvalidSetList:
		m = "保存的列表不合法"
	case InvalidAddList:
		m = "添加的元素不合法"
	case InvalidDelList:
		m = "删除的元素不合法"
	case InvalidNews:
		m = "非法的新闻"
	case InvalidNewsList:
		m = "非法的新闻列表"
	default:
		m = "未知错误"
	}
	json.NewEncoder(w).Encode(ErrorResponse{errorCode, m})
}

type OkResponse struct {
	Data interface{} `json:"data"`
}

func validate(text, reg string) (string, bool) {
	r := regexp.MustCompile("^" + reg + "$")
	return text, r.MatchString(text)
}

var UserArray = make([]User, 0)
var UserTokenMapID = make(map[string]int)
var UsernameMapID = make(map[string]int)
var EmailMapID = make(map[string]int)

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
	CategoryList      []string `json:"-"`
	SearchHistoryList []string `json:"-"`
	FavoriteList      []Item   `json:"-"`
	HistoryList       []Item   `json:"-"`
}

type RegisterResponse struct {
	ID    int    `json:"id"`
	Token string `json:"token"`
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
	user := User{new(sync.RWMutex), ID, username, password, email, "", token, make([]string, 0), make([]string, 0), make([]Item, 0), make([]Item, 0)}
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

func webUserInfo(w http.ResponseWriter, r *http.Request) {
	if !checkForm(w, r) {
		return
	}
	token := r.Form.Get("token")
	if ID, ok := getIDFromToken(token); ok {
		user := &UserArray[ID]
		user.lock.RLock()
		defer user.lock.RUnlock()
		json.NewEncoder(w).Encode(user)
		return
	}
	webReturnError(w, InvalidToken)
}

func webUserEdit(w http.ResponseWriter, r *http.Request) {
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

func reverse1(a []string) []string {
	ret := make([]string, len(a))
	for i := 0; i < len(a); i++ {
		ret[i] = a[len(a)-1-i]
	}
	return ret
}

func reverse2(a []Item) []Item {
	ret := make([]Item, len(a))
	for i := 0; i < len(a); i++ {
		ret[i] = a[len(a)-1-i]
	}
	return ret
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
		var resp OkResponse
		switch listType {
		case "category":
			resp = OkResponse{reverse1(user.CategoryList[skip:end])}
		case "search_history":
			resp = OkResponse{reverse1(user.SearchHistoryList[skip:end])}
		case "favorite":
			resp = OkResponse{reverse2(user.FavoriteList[skip:end])}
		case "history":
			resp = OkResponse{reverse2(user.HistoryList[skip:end])}
		}
		json.NewEncoder(w).Encode(resp)
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
			webReturnError(w, InvalidSetList)
			return
		}
	} else {
		if err := json.Unmarshal([]byte(r.Form.Get("data")), &data2); err != nil {
			webReturnError(w, InvalidSetList)
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
			user.CategoryList = reverse1(data1)
		case "search_history":
			user.SearchHistoryList = reverse1(data1)
		case "favorite":
			user.FavoriteList = reverse2(data2)
		case "history":
			user.HistoryList = reverse2(data2)
		}
		fmt.Fprintf(w, "{}")
		return
	}
	webReturnError(w, InvalidToken)
}

func webAddList(w http.ResponseWriter, r *http.Request) {
	if !checkForm(w, r) {
		return
	}
	token := r.Form.Get("token")
	listType, ok := validate(r.Form.Get("type"), `(category|search_history|favorite|history)`)
	if !ok {
		webReturnError(w, InvalidListType)
		return
	}
	var data1 string
	var data2 Item
	if listType == "category" || listType == "search_history" {
		data1 = r.Form.Get("data")
	} else {
		if err := json.Unmarshal([]byte(r.Form.Get("data")), &data2); err != nil {
			webReturnError(w, InvalidAddList)
			return
		}
	}
	if ID, ok := getIDFromToken(token); ok {
		user := &UserArray[ID]
		user.lock.Lock()
		defer user.lock.Unlock()
		switch listType {
		case "category":
			user.CategoryList = append(user.CategoryList, data1)
		case "search_history":
			user.SearchHistoryList = append(user.SearchHistoryList, data1)
		case "favorite":
			user.FavoriteList = append(user.FavoriteList, data2)
		case "history":
			user.HistoryList = append(user.HistoryList, data2)
		}
		fmt.Fprintf(w, "{}")
		return
	}
	webReturnError(w, InvalidToken)
}

func remove1(a []string, key string) []string {
	for i := 0; i < len(a); i++ {
		if a[i] == key {
			return a[:i+copy(a[i:], a[i+1:])]
		}
	}
	return a
}

func remove2(a []Item, key string) []Item {
	for i := 0; i < len(a); i++ {
		if a[i].NewsID == key {
			return a[:i+copy(a[i:], a[i+1:])]
		}
	}
	return a
}

func webDelList(w http.ResponseWriter, r *http.Request) {
	if !checkForm(w, r) {
		return
	}
	token := r.Form.Get("token")
	listType, ok := validate(r.Form.Get("type"), `(category|search_history|favorite|history)`)
	if !ok {
		webReturnError(w, InvalidListType)
		return
	}
	data := r.Form.Get("data")
	if ID, ok := getIDFromToken(token); ok {
		user := &UserArray[ID]
		user.lock.Lock()
		defer user.lock.Unlock()
		switch listType {
		case "category":
			user.CategoryList = remove1(user.CategoryList, data)
		case "search_history":
			user.SearchHistoryList = remove1(user.SearchHistoryList, data)
		case "favorite":
			user.FavoriteList = remove2(user.FavoriteList, data)
		case "history":
			user.HistoryList = remove2(user.HistoryList, data)
		}
		fmt.Fprintf(w, "{}")
		return
	}
	webReturnError(w, InvalidToken)
}

func has1(a []string, key string) bool {
	for i := 0; i < len(a); i++ {
		if a[i] == key {
			return true
		}
	}
	return false
}

func has2(a []Item, key string) bool {
	for i := 0; i < len(a); i++ {
		if a[i].NewsID == key {
			return true
		}
	}
	return false
}

func webHasList(w http.ResponseWriter, r *http.Request) {
	if !checkForm(w, r) {
		return
	}
	token := r.Form.Get("token")
	listType, ok := validate(r.Form.Get("type"), `(category|search_history|favorite|history)`)
	if !ok {
		webReturnError(w, InvalidListType)
		return
	}
	data := r.Form.Get("data")
	if ID, ok := getIDFromToken(token); ok {
		user := &UserArray[ID]
		user.lock.RLock()
		has := false
		defer user.lock.RUnlock()
		switch listType {
		case "category":
			has = has1(user.CategoryList, data)
		case "search_history":
			has = has1(user.SearchHistoryList, data)
		case "favorite":
			has = has2(user.FavoriteList, data)
		case "history":
			has = has2(user.HistoryList, data)
		}
		json.NewEncoder(w).Encode(OkResponse{has})
		return
	}
	webReturnError(w, InvalidToken)
}

type ScoreData struct {
	Score float64 `json:"score"`
	Word  string  `json:"word"`
}

type News struct {
	ID          string      `json:"newsID"`
	Title       string      `json:"title"`
	Content     string      `json:"content"`
	PublishTime string      `json:"publishTime"`
	Category    string      `json:"category"`
	Image       string      `json:"image"`
	Video       string      `json:"video"`
	Publisher   string      `json:"publisher"`
	Keywords    []ScoreData `json:"keywords"`
}

var NewsMap = make(map[string]News)
var NewsMutex sync.RWMutex

func webAddNews(w http.ResponseWriter, r *http.Request) {
	if !checkForm(w, r) {
		return
	}
	var news News
	if err := json.Unmarshal([]byte(r.Form.Get("data")), &news); err != nil {
		webReturnError(w, InvalidNews)
		return
	}
	NewsMutex.Lock()
	NewsMap[news.ID] = news
	NewsMutex.Unlock()
	fmt.Fprintf(w, "{}")
}

func webGetNews(w http.ResponseWriter, r *http.Request) {
	if !checkForm(w, r) {
		return
	}
	var IDList []string
	if err := json.Unmarshal([]byte(r.Form.Get("data")), &IDList); err != nil {
		webReturnError(w, InvalidNewsList)
		return
	}
	var data []News
	NewsMutex.RLock()
	for _, id := range IDList {
		if news, ok := NewsMap[id]; ok {
			data = append(data, news)
		}
	}
	NewsMutex.RUnlock()
	json.NewEncoder(w).Encode(OkResponse{data})
}

func main() {
	http.HandleFunc("/register", webRegister)
	http.HandleFunc("/login", webLogin)
	http.HandleFunc("/userInfo", webUserInfo)
	http.HandleFunc("/userEdit", webUserEdit)
	http.HandleFunc("/getList", webGetList)
	http.HandleFunc("/setList", webSetList)
	http.HandleFunc("/addList", webAddList)
	http.HandleFunc("/delList", webDelList)
	http.HandleFunc("/hasList", webHasList)
	http.HandleFunc("/addNews", webAddNews)
	http.HandleFunc("/getNews", webGetNews)
	log.Fatal(http.ListenAndServe(":18888", nil))
}
