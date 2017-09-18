package godiscoveryservice

import (
	"crypto"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"net/http"
	"regexp"
	"strings"
)

type (
	Conf struct {
		DiscoMetaData string
		SpMetaData    string
	}

	idpInfoIn struct {
		EntityID     string        `json:"entityid"`
		DisplayNames []displayName `json:"DisplayNames"`
	}

	idpInfoOut struct {
		EntityID     string            `json:"entityID"`
		DisplayNames map[string]string `json:"DisplayNames"`
		Keywords     string            `json:"Keywords"`
	}

	displayName struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	}

	response struct {
		Spok        bool            `json:"spok"`
		Chosen      map[string]bool `json:"chosen"`
		Found       int             `json:"found"`
		Rows        int             `json:"rows"`
		Feds        []string        `json:"feds"`
		Idps        []idpInfoOut    `json:"idps"`
		Logo        string          `json:"logo"`
		DisplayName string          `json:"displayname"`
	}
)

var (
	Config               = Conf{}
	dotdashpling         = regexp.MustCompile("[\\.\\-\\']")
	notword              = regexp.MustCompile("[^\\w]")
	whitespace           = regexp.MustCompile("[\\s]+|\\z")
	notwordnorwhitespace = regexp.MustCompile("[^\\s\\w]")
)

// Only for logging response
func DSTiming(w http.ResponseWriter, r *http.Request) (err error) {
	return
}

func DSBackend(w http.ResponseWriter, r *http.Request) (err error) {
	var md string
	var spMetaData *goxml.Xp
	var res response
	res.Chosen = map[string]bool{}
	r.ParseForm()
	entityID := r.Form.Get("entityID")
	query := strings.ToLower(string2Latin(r.Form.Get("query")))
	res.Feds = strings.Split(r.Form.Get("feds"), ",")
	res.Idps = []idpInfoOut{}
	chosen := strings.Split(r.Form.Get("chosen"), ",")

	if entityID != "" {
		db, err := sql.Open("sqlite3", Config.SpMetaData)
		if err != nil {
			return err
		}
		defer db.Close()
		ent := hex.EncodeToString(goxml.Hash(crypto.SHA1, entityID))
		var query = "select e.md md from entity_HYBRID_INTERNAL e, lookup_HYBRID_INTERNAL l where l.hash = ? and l.entity_id_fk = e.id"
		err = db.QueryRow(query, ent).Scan(&md)
		if err != nil {
			return err
		}
		md = string(gosaml.Inflate([]byte(md)))
		spMetaData = goxml.NewXp(md)
		res.Logo = spMetaData.Query1(nil, "md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Logo")
		for _, l := range []string{"en"} {
			res.DisplayName = spMetaData.Query1(nil, "md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang='"+l+"']")
			fmt.Println("displayname", res.DisplayName, "md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang='"+l+"']")
			if res.DisplayName != "" {
				break
			}
		}
		if res.Feds[0] == "" {
			res.Feds = spMetaData.QueryMulti(nil, "md:Extensions/wayf:wayf/wayf:feds")
		}
	}

	res.Spok = (entityID == "") == (spMetaData == nil) // both either on or off

	if res.Spok {

		ftsquery := dotdashpling.ReplaceAllLiteralString(query, "0")
		ftsquery = notword.ReplaceAllLiteralString(ftsquery, " ")
		ftsquery = whitespace.ReplaceAllLiteralString(ftsquery, "* ")

		fedsquery := ""
		delim := "("
		for _, fed := range res.Feds {
			fed = notwordnorwhitespace.ReplaceAllLiteralString(fed, "0")
			fedsquery += delim + "feds:" + fed
			delim = " OR "
		}
		fedsquery += ")"

		db, err := sql.Open("sqlite3", Config.DiscoMetaData)
		if err != nil {
			return err
		}
		defer db.Close()

		if chosen[0] != "" {
			chosenquery := "("
			delim = ""
			for _, chosenentity := range chosen {
				chosenentity = notwordnorwhitespace.ReplaceAllLiteralString(chosenentity, "0")
				chosenquery += delim + chosenentity
				delim = " OR "
			}
			chosenquery += ")"
			//fmt.Fprintln(w, "chosenquery", chosenquery + fedsquery)

			rows, err := db.Query("select json from disco where entityid MATCH ? limit 10", chosenquery+fedsquery)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var entityInfo []byte
				err = rows.Scan(&entityInfo)
				if err != nil {
					return err
				}
				var f idpInfoIn
				err = json.Unmarshal(entityInfo, &f)
				res.Chosen[f.EntityID] = true
			}

			err = rows.Err()
			if err != nil {
				return err
			}
		}

		err = db.QueryRow("select count(*) c from disco where keywords MATCH ?", ftsquery+fedsquery).Scan(&res.Found)
		if err != nil {
			return err
		}
		fmt.Println("q:", ftsquery, fedsquery)
		rows, err := db.Query("select json, keywords from disco where keywords MATCH ? limit 100", ftsquery+fedsquery)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var entityInfo []byte
			var keywords string
			err = rows.Scan(&entityInfo, &keywords)
			if err != nil {
				return err
			}

			var f idpInfoIn
			x := idpInfoOut{DisplayNames: map[string]string{}}
			err = json.Unmarshal(entityInfo, &f)
			x.EntityID = f.EntityID
			x.Keywords = keywords
			for _, dn := range f.DisplayNames {
				x.DisplayNames[dn.Lang] = dn.Value
			}

			res.Idps = append(res.Idps, x)
			res.Rows++
			//fmt.Fprintln(w, "f", f)
		}
		err = rows.Err()
		if err != nil {
			return err
		}
	}
	b, err := json.Marshal(res)
	fmt.Fprintln(w, string(b))
	return
}