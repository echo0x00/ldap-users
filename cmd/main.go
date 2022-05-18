package main

import (
	"ldap/internal/config"
	"ldap/internal/db"
	"ldap/internal/utils"
	"log"
	"sync"

	"github.com/go-ldap/ldap/v3"
)

func main() {
	l, err := ldap.DialURL(config.Host)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	err = l.Bind(config.User, config.Pass)
	if err != nil {
		log.Println(err)
	}

	searchReq := ldap.NewSearchRequest(
		"dc=gtrf,dc=local",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectCategory=person)(objectClass=user))",
		[]string{},
		nil,
	)
	result, err := l.Search(searchReq)
	if err != nil {
		log.Fatal(err)
	}

	maxGoroutines := 10 //иначе слишком много одновременных соединений
	guard := make(chan int, maxGoroutines)

	var wg sync.WaitGroup

	for _, entry := range result.Entries {
		fio := entry.GetAttributeValue("name")
		account := entry.GetAttributeValue("sAMAccountName")
		sid := utils.DecodeSid(entry.GetRawAttributeValue("objectSid"))
		email := entry.GetAttributeValue("mail")
		status := entry.GetAttributeValue("userAccountControl")

		guard <- 1
		wg.Add(1)

		go func() {
			defer wg.Done()
			db.CheckUser(fio, account, sid, email, utils.IsAccountEnabled(status))
			<-guard
		}()
	}

	wg.Wait()

}
