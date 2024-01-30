package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

type authStruct struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

type fileBeginReqStruct struct {
	Docid  string `json:"docid"`
	Length int    `json:"length"`
	Name   string `json:"name"`
}

type fileBeginRspStruct struct {
	Authrequest []string `json:"authrequest"`
	Docid       string   `json:"docid"`
	Name        string   `json:"name"`
	Rev         string   `json:"rev"`
}

type fileEndReqStruct struct {
	Docid string `json:"docid"`
	Rev   string `json:"rev"`
}

type fileUploadRespStruct struct {
	Docid string `json:"docid"`
	Token string `json:"token"`
}

type doclibRspStruct struct {
	Entries []struct {
		CreatedAt string `json:"created_at"`
		CreatedBy struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"created_by"`
		ID      string `json:"id"`
		Name    string `json:"name"`
		OwnedBy []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"owned_by"`
		Quota struct {
			Allocated int64 `json:"allocated"`
			Used      int   `json:"used"`
		} `json:"quota"`
		Subtype struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"subtype"`
		Type string `json:"type"`
	} `json:"entries"`
	TotalCount int `json:"total_count"`
}

func main() {

	router := gin.Default()

	//Upload file into AnyShare
	router.POST("/api/uploadfile", uploadFile)

	//Get Document Library
	router.POST("/api/doclib", getDocumentLibrary)

	router.Run(":50016")
}

func uploadFile(c *gin.Context) {

	// // 从请求body中读取内容
	// body, err := io.ReadAll(c.Request.Body)
	// if err != nil {
	// 	c.String(http.StatusBadRequest, "Bad request")
	// 	return
	// }
	// len := len(body)
	// str := string(body)

	docid := c.PostForm("docid")
	url := c.PostForm("url")
	token := c.PostForm("token")

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.String(http.StatusBadRequest, "文件上传失败")
	}

	body, err := io.ReadAll(file)
	if err != nil {
		c.String(http.StatusBadRequest, "Bad Request")
	}
	//fmt.Println(file, header, body)

	//获取Token
	// token := getToken()

	//开始上传文件
	fileBeginRsp := fileBegin(token, int(header.Size), header.Filename, docid, url)

	// 处理上传文件
	fileProcessing(token, body, fileBeginRsp)

	// //结束上传文件
	fileEnd(token, fileBeginRsp, url)

	var fileUploadResp fileUploadRespStruct
	fileUploadResp.Docid = fileBeginRsp.Docid
	fileUploadResp.Token = token
	c.IndentedJSON(http.StatusOK, fileUploadResp)
}

func getToken() string {

	authorization := "Basic MTNjOGQ2NmUtN2Q0OC00ZWY2LWE0Y2EtYzY3NGU2ODExNTgyOjExMTExMQ=="
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	urlValues := url.Values{}

	//添加Form Body字段值
	urlValues.Add("grant_type", "client_credentials")
	urlValues.Add("scope", "all")

	reqBody := urlValues.Encode()
	requestPostURL := "https://10.4.132.181:443/oauth2/token"
	req, err := http.NewRequest(http.MethodPost, requestPostURL, strings.NewReader(reqBody))

	//添加Header
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	req.Header.Add("Authorization", authorization)

	if err != nil {
		log.Println(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
	}

	var auth authStruct
	err = json.NewDecoder(resp.Body).Decode(&auth)
	if err != nil {
		log.Println(err)
	}
	token := auth.AccessToken

	defer resp.Body.Close()
	return token
}

func fileBegin(token string, len int, filename, docid, url string) fileBeginRspStruct {

	authorization := "Bearer " + token
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	var data fileBeginReqStruct
	// data.Docid = "gns://AFC10D84B461408EAD3CEBA6E0EC136F"
	data.Docid = docid
	data.Length = len
	data.Name = filename
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshalling JSON:", err)

	}

	// requestPostURL := "https://10.4.132.181:443/api/efast/v1/file/osbeginupload"
	requestPostURL := url + "/api/efast/v1/file/osbeginupload"
	req, err := http.NewRequest(http.MethodPost, requestPostURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Println(err)
	}
	//添加Header
	// req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	req.Header.Add("Authorization", authorization)
	// fmt.Println(string(authorization))

	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
	}

	var fileBeginRsp fileBeginRspStruct
	err = json.NewDecoder(resp.Body).Decode(&fileBeginRsp)
	if err != nil {
		log.Println(err)
	}
	return fileBeginRsp
}

func fileProcessing(token string, body []byte, fileBeginRsp fileBeginRspStruct) {

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	requestPostURL := fileBeginRsp.Authrequest[1]

	// var body1 =
	req, err := http.NewRequest(http.MethodPut, requestPostURL, bytes.NewReader(body))

	//添加Header

	//Content-Type
	req.Header.Add("Content-Type", "application/octet-stream")

	//date
	str := fileBeginRsp.Authrequest[4]
	fmt.Println(str)
	lenStr := len(str)
	slice := str[12:lenStr]
	//slice := strings.Split(str, ":")
	req.Header.Add("x-amz-date", slice)

	//Authorization
	str = fileBeginRsp.Authrequest[2]
	lenStr = len(str)
	slice = str[15:lenStr]
	req.Header.Add("Authorization", slice)

	// fmt.Println(string(authorization))
	if err != nil {
		log.Println(err)
	}
	fmt.Println(req.Header)

	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
	}

	respData, _ := io.ReadAll(req.Body)
	// var fileProcessingRsp filePorcessingRspStruct
	// err = json.NewDecoder(resp.Body).Decode(&fileProcessingRsp)
	// if err != nil {
	// 	log.Println(err)
	// }
	fmt.Println("fileProcessing", resp.Status)
	fmt.Println("res", respData)
	// return fileBeginRsp
}
func fileEnd(token string, fileBeginRsp fileBeginRspStruct, url string) {

	authorization := "Bearer " + token
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	var data fileEndReqStruct
	data.Docid = fileBeginRsp.Docid
	data.Rev = fileBeginRsp.Rev
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshalling JSON:", err)

	}

	// requestPostURL := "https://10.4.132.181:443/api/efast/v1/file/osendupload"
	requestPostURL := url + "/api/efast/v1/file/osendupload"
	req, err := http.NewRequest(http.MethodPost, requestPostURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Println(err)
	}
	//添加Header
	// req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	req.Header.Add("Authorization", authorization)

	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
	}

	fmt.Println(resp.Status)
}

func getDocumentLibrary(c *gin.Context) {
	docname := c.PostForm("docname")
	host := c.PostForm("url")
	username := c.PostForm("username")
	password := c.PostForm("password")
	// fmt.Println(docname)
	//docname := c.Query("docname")
	fmt.Println(docname)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	//获取Token
	token := getAsToken(host, username, password)

	authorization := "Bearer " + token

	// requestURL := "https://10.4.132.181:443/api/efast/v1/doc-lib/custom"
	requestURL := host + "/api/efast/v1/doc-lib/custom"

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		log.Println(err)
	}
	q := req.URL.Query()
	q.Add("offset", "0")
	q.Add("limit", "10")
	req.URL.RawQuery = q.Encode()

	//添加Header
	req.Header.Add("Authorization", authorization)

	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
	}

	body, err := io.ReadAll(resp.Body)
	//jsonData, err := json.Marshal(resp.Body)
	if err != nil {
		log.Println(err)
	}

	// 解析JSON数据
	var doclibRsp doclibRspStruct
	err = json.Unmarshal(body, &doclibRsp)
	if err != nil {
		fmt.Println("解析JSON失败:", err)
	}

	var docid string
	for _, value := range doclibRsp.Entries {
		if value.Name == docname {
			docid = value.ID
			break
		}

	}
	fmt.Println(docid)

	defer resp.Body.Close()

	var setResp fileUploadRespStruct
	setResp.Docid = docid
	setResp.Token = token

	c.IndentedJSON(http.StatusOK, setResp)
}

func getAsToken(host, username, password string) (token string) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	urlValues := url.Values{}

	//添加Form Body字段值
	urlValues.Add("grant_type", "client_credentials")
	urlValues.Add("scope", "all")
	reqBody := urlValues.Encode()

	requestPostURL := host + "/oauth2/token"
	req, err := http.NewRequest(http.MethodPost, requestPostURL, strings.NewReader(reqBody))
	if err != nil {
		log.Println(err)
	}
	//添加Header
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	req.SetBasicAuth(username, password)
	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer res.Body.Close()

	var auth authStruct
	err = json.NewDecoder(res.Body).Decode(&auth)
	if err != nil {
		log.Println(err)
	}
	token = auth.AccessToken

	return token

}
