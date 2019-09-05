# MoYu 后端

## 安装

go 版本大于等于 1.12

`$ go build server.go`

## 使用

直接运行编译得到的文件，默认端口为 18888

前端可以用 [test.html](./test.html) 来测试。

## API

发生错误会返回

```json
{
    "error":1, // 一个整数，表示错误代码
    "msg":"发生了错误" // 错误信息
}
```

### POST /register

用户注册

| name     | value                    | 描述     |
| -------- | ------------------------ | -------- |
| username | aaa                      | 用户名   |
| password | aaaaaa                   | 密码     |
| email    | aaa@aa.com               | 邮箱     |
| avatar   | http://www.aaa.com/a.png | 头像链接 |

成功则返回

```json
{
    "id":1, // 一个整数，表示用户id
    "token":"15C174D7BED730704D65822107FCFD5278629A0F5F3F164FD5104DC76695721D"
}
```

### POST /login

用户登录

| name     | value                    | 描述     |
| -------- | ------------------------ | -------- |
| username | aaa                      | 用户名   |
| password | aaaaaa                   | 密码     |
| email    | aaa@aa.com               | 邮箱     |
| avatar   | http://www.aaa.com/a.png | 头像链接 |

成功则返回

```json
{
    "id":0,
    "username":"aaa",
    "email":"aaaa@aa.com",
    "avatar":"",
    "token":"15C174E38B933784B80704BB7B4D7C03365A858149C6E2D157E9D1860D1D68D8",
    "category_list":[],
    "favorite_list":[],
    "history_list":[]
}
```

### POST /userInfo

获取用户信息

| name  | value                                                        |
| ----- | ------------------------------------------------------------ |
| token | 15C174E38B933784B80704BB7B4D7C03365A858149C6E2D157E9D1860D1D68D8 |

成功则返回

```json
{
	"id":0,
	"username":"aaa",
	"email":"aaaa@aa.com",
	"avatar":"http://www.xxx.com/1.png"
}
```

### POST /userEdit

用户修改头像

| name   | value                                                        |
| ------ | ------------------------------------------------------------ |
| token  | 15C174E38B933784B80704BB7B4D7C03365A858149C6E2D157E9D1860D1D68D8 |
| avatar | http://www.aaa.com/a.png                                     |

成功则返回

```json
{}
```

### POST /getList

获取列表

| name  | value                                                        | 描述                                             |
| ----- | ------------------------------------------------------------ | ------------------------------------------------ |
| token | 15C174E38B933784B80704BB7B4D7C03365A858149C6E2D157E9D1860D1D68D8 |                                                  |
| type  | category                                                     | category、search_history、favorite、history 之一 |
| skip  | 0                                                            | 跳过多少个                                       |
| limit | -1                                                           | 返回的条数。-1表示无限制                         |

成功则返回（category 和 search_history）

```json
{
	"data": ["a","b"]
}
```

或者（favorite 和 history）

```json
{
	"data": [{"news_id":"a","time":"gg"}]
}
```

### POST /setList

设置列表

| name  | value                                                        |
| ----- | ------------------------------------------------------------ |
| token | 15C174E38B933784B80704BB7B4D7C03365A858149C6E2D157E9D1860D1D68D8 |
| type  | category                                                     |
| data  | ["a","b"] 或者 [{"news_id":"a","time":"gg"}]                 |

成功则返回

```json
{}
```

### POST /addList

添加元素到列表前

| name  | value                                                        |
| ----- | ------------------------------------------------------------ |
| token | 15C174E38B933784B80704BB7B4D7C03365A858149C6E2D157E9D1860D1D68D8 |
| type  | category                                                     |
| data  | a 或者 {"news_id":"a","time":"gg"}                           |

成功则返回

```json
{}
```

### POST /delList

删除元素内值相同的元素

| name  | value                                                        |
| ----- | ------------------------------------------------------------ |
| token | 15C174E38B933784B80704BB7B4D7C03365A858149C6E2D157E9D1860D1D68D8 |
| type  | category                                                     |
| data  | a 或者 news_id                        |

成功则返回

```json
{}
```

### POST /hasList

判断元素是否存在

| name  | value                                                        |
| ----- | ------------------------------------------------------------ |
| token | 15C174E38B933784B80704BB7B4D7C03365A858149C6E2D157E9D1860D1D68D8 |
| type  | category                                                     |
| data  | a 或者 news_id                        |

成功则返回

```json
{
	"data": true
}
```

### POST /addNews

缓存新闻

| name  | value                                                        |
| ----- | ------------------------------------------------------------ |
| data  | {"newsID":"id","title":"gg", "content":"hh","publishTime":"aa","category":"tt","image":"[]","video":"","publisher":"no","keywords":[]}                        |

成功则返回

```json
{}
```

### POST /getNews

根据 newsID 列表获取新闻列表

| name  | value                                                        |
| ----- | ------------------------------------------------------------ |
| data  | ["id"]                       |

成功则返回

```json
{
    "data":[
        {
            "newsID":"id",
            "title":"gg",
            "content":"hh",
            "publishTime":"aa",
            "category":"tt",
            "image":"[]",
            "video":"",
            "publisher":"no",
            "keywords":[]
        }
    ]
}
```
