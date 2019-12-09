package gomail

import (
	"fmt"
	"gopkg.in/gomail.v2"
	"strings"
	"time"

	mail "github.com/go-gomail/gomail"
)

var (
	fromAddress = "traffic_err@huibo-eparking.com"
	toAddress   = "2531868871@qq.com"
	smtpHost    = "smtp.exmail.qq.com"
	smtpPort    = 465
	username    = "traffic_err@huibo-eparking.com"
	password    = "Hb123456"
)

func Send(title string, body ...string) {
	sendMail(title, body)
}

func sendMail(title string, body []string) {
	date := time.Now().Format("01-02")
	content := strings.Join(body, "\n")
	m := mail.NewMessage()
	m.SetAddressHeader("From", fromAddress, "系统邮件")
	m.SetHeader("To", m.FormatAddress(toAddress, "收件人"))
	m.SetHeader("Subject", fmt.Sprintf("[%s]错误报告: %s", date, title))
	m.SetBody("text/plain", content)

	d := gomail.NewDialer(smtpHost, smtpPort, username, password)
	if err := d.DialAndSend(m); err != nil {
		fmt.Printf("发送失败: %s\n", err)
		return
	}
}
