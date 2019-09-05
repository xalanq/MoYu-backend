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
    "error": 1, // 一个整数，表示错误代码
    "msg": "发生了错误" // 错误信息
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
    "id": 1, // 一个整数，表示用户 id
    "token": "15C174D7BED730704D65822107FCFD5278629A0F5F3F164FD5104DC76695721D" // 授权 token
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
    // 此 token 是新产生的，之前的 token 会失效
    "token":"15C174E38B933784B80704BB7B4D7C03365A858149C6E2D157E9D1860D1D68D8",
    "category_list":[],
    "favorite_list":[],
    "history_list":[]
}
```

### POST /user

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

| name  | value                                                        | 描述                             |
| ----- | ------------------------------------------------------------ | -------------------------------- |
| token | 15C174E38B933784B80704BB7B4D7C03365A858149C6E2D157E9D1860D1D68D8 |                                  |
| type  | category                                                     | category、favorite、history 之一 |

成功则返回

```json
["a","b"]
```

### POST /setList

设置列表

| name  | value                                                        | 描述                             |
| ----- | ------------------------------------------------------------ | -------------------------------- |
| token | 15C174E38B933784B80704BB7B4D7C03365A858149C6E2D157E9D1860D1D68D8 |                                  |
| type  | category                                                     | category、favorite、history 之一 |
| data  | ["a","b"]                                                    | 列表的数据                       |

成功则返回

```json
{}
```