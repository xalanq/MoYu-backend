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
	InvalidTags
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
	case InvalidTags:
		m = "非法的标签"
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
	ID                    int                `json:"id"`
	Username              string             `json:"username"`
	Password              string             `json:"-"`
	Email                 string             `json:"email"`
	Avatar                string             `json:"avatar"`
	AvatarLock            *sync.RWMutex      `json:"-"`
	Token                 string             `json:"token"`
	TokenLock             *sync.RWMutex      `json:"-"`
	CategoryList          []string           `json:"-"`
	CategoryListLock      *sync.RWMutex      `json:"-"`
	SearchHistoryList     []string           `json:"-"`
	SearchHistoryListLock *sync.RWMutex      `json:"-"`
	FavoriteList          []Item             `json:"-"`
	FavoriteListLock      *sync.RWMutex      `json:"-"`
	HistoryList           []Item             `json:"-"`
	HistoryListLock       *sync.RWMutex      `json:"-"`
	Tags                  map[string]float64 `json:"-"`
	TagsLock              *sync.RWMutex      `json:"-"`
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
	user := User{ID, username, password, email,
		"", new(sync.RWMutex),
		token, new(sync.RWMutex),
		reverse1([]string{"1社会", "1娱乐", "1体育", "1科技", "1军事", "0教育", "0文化", "0健康", "0财经", "0汽车"}), new(sync.RWMutex),
		make([]string, 0), new(sync.RWMutex),
		make([]Item, 0), new(sync.RWMutex),
		make([]Item, 0), new(sync.RWMutex),
		make(map[string]float64), new(sync.RWMutex)}
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
			user.TokenLock.Lock()
			defer user.TokenLock.Unlock()
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
		user.AvatarLock.RLock()
		defer user.AvatarLock.RUnlock()
		user.TokenLock.RLock()
		defer user.TokenLock.RUnlock()
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
		user.AvatarLock.Lock()
		user.Avatar = avatar
		user.AvatarLock.Unlock()
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
		num := 0
		gg := func() OkResponse {
			switch listType {
			case "category":
				user.CategoryListLock.RLock()
				defer user.CategoryListLock.RUnlock()
				num = len(user.CategoryList)
			case "search_history":
				user.SearchHistoryListLock.RLock()
				defer user.SearchHistoryListLock.RUnlock()
				num = len(user.SearchHistoryList)
			case "favorite":
				user.FavoriteListLock.RLock()
				defer user.FavoriteListLock.RUnlock()
				num = len(user.FavoriteList)
			case "history":
				user.HistoryListLock.RLock()
				defer user.HistoryListLock.RUnlock()
				num = len(user.HistoryList)
			}
			end := skip + limit
			if limit == -1 || end > num {
				end = num
			}
			if skip >= end {
				return OkResponse{make([]string, 0)}
			}
			switch listType {
			case "category":
				return OkResponse{reverse1(user.CategoryList[skip:end])}
			case "search_history":
				return OkResponse{reverse1(user.SearchHistoryList[skip:end])}
			case "favorite":
				return OkResponse{reverse2(user.FavoriteList[skip:end])}
			case "history":
				return OkResponse{reverse2(user.HistoryList[skip:end])}
			}
			return OkResponse{make([]string, 0)}
		}
		json.NewEncoder(w).Encode(gg())
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
		switch listType {
		case "category":
			user.CategoryListLock.Lock()
			user.CategoryList = reverse1(data1)
			user.CategoryListLock.Unlock()
		case "search_history":
			user.SearchHistoryListLock.Lock()
			user.SearchHistoryList = reverse1(data1)
			user.SearchHistoryListLock.Unlock()
		case "favorite":
			user.FavoriteListLock.Lock()
			user.FavoriteList = reverse2(data2)
			user.FavoriteListLock.Unlock()
		case "history":
			user.HistoryListLock.Lock()
			user.HistoryList = reverse2(data2)
			user.HistoryListLock.Unlock()
		}
		fmt.Fprintf(w, "{}")
		return
	}
	webReturnError(w, InvalidToken)
}

var hotWord = make(map[string]int)

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
		switch listType {
		case "category":
			user.CategoryListLock.Lock()
			user.CategoryList = append(user.CategoryList, data1)
			user.CategoryListLock.Unlock()
		case "search_history":
			user.SearchHistoryListLock.Lock()
			hotWord[data1]++
			flag := true
			for _, i := range user.SearchHistoryList {
				if i == data1 {
					flag = false
					break
				}
			}
			if flag {
				user.SearchHistoryList = append(user.SearchHistoryList, data1)
			}
			user.SearchHistoryListLock.Unlock()
		case "favorite":
			user.FavoriteListLock.Lock()
			user.FavoriteList = append(user.FavoriteList, data2)
			user.FavoriteListLock.Unlock()
		case "history":
			user.HistoryListLock.Lock()
			flag := true
			for _, i := range user.HistoryList {
				if i.NewsID == data2.NewsID {
					flag = false
					break
				}
			}
			if flag {
				user.HistoryList = append(user.HistoryList, data2)
			}
			user.HistoryListLock.Unlock()
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
		switch listType {
		case "category":
			user.CategoryListLock.Lock()
			user.CategoryList = remove1(user.CategoryList, data)
			user.CategoryListLock.Unlock()
		case "search_history":
			user.SearchHistoryListLock.Lock()
			user.SearchHistoryList = remove1(user.SearchHistoryList, data)
			user.SearchHistoryListLock.Unlock()
		case "favorite":
			user.FavoriteListLock.Lock()
			user.FavoriteList = remove2(user.FavoriteList, data)
			user.FavoriteListLock.Unlock()
		case "history":
			user.HistoryListLock.Lock()
			user.HistoryList = remove2(user.HistoryList, data)
			user.HistoryListLock.Unlock()
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
		has := false
		switch listType {
		case "category":
			user.CategoryListLock.RLock()
			has = has1(user.CategoryList, data)
			user.CategoryListLock.RUnlock()
		case "search_history":
			user.SearchHistoryListLock.RLock()
			has = has1(user.SearchHistoryList, data)
			user.SearchHistoryListLock.RUnlock()
		case "favorite":
			user.FavoriteListLock.RLock()
			has = has2(user.FavoriteList, data)
			user.FavoriteListLock.RUnlock()
		case "history":
			user.HistoryListLock.RLock()
			has = has2(user.HistoryList, data)
			user.HistoryListLock.RUnlock()
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

type MentionData struct {
	Count int    `json:"count"`
	Url   string `json:"linkedURL"`
	Word  string `json:"mention"`
}

type LocationData struct {
	Longitude float64 `json:"lng"`
	Latitude  float64 `json:"lat"`
	Count     int     `json:"count"`
	Url       string  `json:"linkedURL"`
	Word      string  `json:"mention"`
}

type News struct {
	ID            string         `json:"newsID"`
	Title         string         `json:"title"`
	Content       string         `json:"content"`
	PublishTime   string         `json:"publishTime"`
	Language      string         `json:"language"`
	Category      string         `json:"category"`
	Image         string         `json:"image"`
	Video         string         `json:"video"`
	Publisher     string         `json:"publisher"`
	Keywords      []ScoreData    `json:"keywords"`
	When          []ScoreData    `json:"when"`
	Where         []ScoreData    `json:"where"`
	Who           []ScoreData    `json:"who"`
	Organizations []MentionData  `json:"organizations"`
	Person        []MentionData  `json:"persons"`
	Location      []LocationData `json:"locations"`
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
	data := make([]News, 0)
	NewsMutex.RLock()
	for _, id := range IDList {
		if news, ok := NewsMap[id]; ok {
			data = append(data, news)
		}
	}
	NewsMutex.RUnlock()
	json.NewEncoder(w).Encode(OkResponse{data})
}

func webAddTags(w http.ResponseWriter, r *http.Request) {
	if !checkForm(w, r) {
		return
	}
	token := r.Form.Get("token")
	var data []ScoreData
	if err := json.Unmarshal([]byte(r.Form.Get("data")), &data); err != nil {
		webReturnError(w, InvalidTags)
		return
	}
	if ID, ok := getIDFromToken(token); ok {
		user := &UserArray[ID]
		user.TagsLock.Lock()
		for _, d := range data {
			user.Tags[d.Word] += d.Score
		}
		user.TagsLock.Unlock()
		fmt.Fprintf(w, "{}")
		return
	}
	webReturnError(w, InvalidToken)
}

func webGetTags(w http.ResponseWriter, r *http.Request) {
	if !checkForm(w, r) {
		return
	}
	token := r.Form.Get("token")
	limit := -1
	if tmp, err := strconv.Atoi(r.Form.Get("limit")); err == nil && tmp >= -1 {
		limit = tmp
	}
	if ID, ok := getIDFromToken(token); ok {
		user := &UserArray[ID]

		type kv struct {
			K string
			V float64
		}

		user.TagsLock.RLock()
		ss := make([]kv, len(user.Tags))
		i := 0
		for k, v := range user.Tags {
			ss[i] = kv{k, v}
			i++
		}
		user.TagsLock.RUnlock()

		sort.Slice(ss, func(i, j int) bool {
			return ss[i].V > ss[j].V
		})

		if limit == -1 || limit > len(ss) {
			limit = len(ss)
		}

		data := make([]string, limit)
		for i := 0; i < limit; i++ {
			data[i] = ss[i].K
		}

		json.NewEncoder(w).Encode(OkResponse{data})
		return
	}
	webReturnError(w, InvalidToken)
}

func webHotWord(w http.ResponseWriter, r *http.Request) {
	limit := 10
	if limit > len(hotWord) {
		limit = len(hotWord)
	}

	type kv struct {
		K string
		V int
	}

	ss := make([]kv, len(hotWord))
	i := 0
	for k, v := range hotWord {
		ss[i] = kv{k, v}
		i++
	}

	sort.Slice(ss, func(i, j int) bool {
		return ss[i].V > ss[j].V
	})

	data := make([]string, limit)
	for i := 0; i < limit; i++ {
		data[i] = ss[i].K
	}

	json.NewEncoder(w).Encode(OkResponse{data})
}

func main() {
	hotWord["特朗普"] = 1
	hotWord["香港"] = 2
	hotWord["方舟编译器开源"] = 0
	hotWord["iPhone 11曝光"] = 0
	hotWord["华为发布 Freebuds3"] = 2
	hotWord["华为发布 5G 芯片"] = 1
	hotWord["iG 3:2 JDG"] = 1
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
	http.HandleFunc("/addTags", webAddTags)
	http.HandleFunc("/getTags", webGetTags)
	http.HandleFunc("/hotWord", webHotWord)
	log.Fatal(http.ListenAndServe(":18888", nil))
}
