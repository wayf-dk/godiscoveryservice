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
	"sync"
	"x.config"
)

type (
	idpInfoIn struct {
		EntityID     string        `json:"entityid"`
		DisplayNames []displayName `json:"DisplayNames"`
	}

	idpInfoOut struct {
		EntityID     string            `json:"entityID"`
		DisplayNames map[string]string `json:"DisplayNames"`
		Relevant     bool              `json:"relevant"`
	}

	spInfoOut struct {
		EntityID          string            `json:"entityID"`
		DisplayNames      map[string]string `json:"DisplayNames"`
		RequestInitiators []string          `json:"RequestInitiators"`
		Logo              string            `json:"Logo"`
	}

	displayName struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	}

	response struct {
		Spok          bool         `json:"spok"`
		Chosen        []idpInfoOut `json:"chosen"`
		Found         int          `json:"found"`
		Rows          int          `json:"rows"`
		Feds          []string     `json:"feds"`
		Idps          []idpInfoOut `json:"idps"`
		Logo          string       `json:"logo"`
		Sp            spInfoOut    `json:"sp"`
		DiscoResponse []string     `json:"discoResponse"`
		DiscoACS      []string     `json:"discoACS"`
		Prioritized   []idpInfoOut `json:"prioritized"`
	}
)

var (
	dotdashpling         = regexp.MustCompile("[\\.\\-\\']")
	notword              = regexp.MustCompile("[^\\w]")
	whitespace           = regexp.MustCompile("[\\s]+|\\z")
	notwordnorwhitespace = regexp.MustCompile("[^\\s\\w]")
	spDB, idpDB          *sql.DB
	lock                 sync.Mutex
)

func MetadataUpdated() {
	lock.Lock()
	defer lock.Unlock()
	if spDB != nil {
		spDB.Close()
		spDB = nil
	}
	if idpDB != nil {
		idpDB.Close()
		idpDB = nil
	}
}

// DSTiming used for only logging response
func DSTiming(w http.ResponseWriter, r *http.Request) (err error) {
	w.Header().Set("Content-Type", "text/plain")
	return
}

// DSBackend takes the request extracts the entityID and returns an IDP
func DSBackend(w http.ResponseWriter, r *http.Request) (err error) {
	lock.Lock()
	defer lock.Unlock()

	var md []byte
	var spMetaData *goxml.Xp
	var res response
	r.ParseForm()
	entityID := r.Form.Get("entityID")
	ftsquery := strings.ToLower(string2Latin(r.Form.Get("query")))
	res.Feds = strings.Split(r.Form.Get("feds"), ",")
	res.Idps = []idpInfoOut{}
	chosen := strings.Split(r.Form.Get("chosen"), ",")
	providerIDs := strings.Split(r.Form.Get("providerids"), ",")
	if spDB == nil {
		spDB, err = sql.Open("sqlite3", config.DiscoSPMetadata)
		if err != nil {
			return
		}
	}

	if idpDB == nil {
		idpDB, err = sql.Open("sqlite3", config.DiscoMetadata)
		if err != nil {
			return
		}
	}

	providerIDsquery := makeQuery(providerIDs, "entityid:")

	if entityID != "" {
		//		defer db.Close()
		ent := hex.EncodeToString(goxml.Hash(crypto.SHA1, entityID))
		//		var query = "select e.md md from entity_HYBRID_INTERNAL e, lookup_HYBRID_INTERNAL l where l.hash = ? and l.entity_id_fk = e.id"
		var query = "select e.md md from entity_HYBRID_EXTERNAL_SP e, lookup_HYBRID_EXTERNAL_SP l where l.hash = ? and l.entity_id_fk = e.id"
		err = spDB.QueryRow(query, ent).Scan(&md)
		if err == nil {
			res.Sp.EntityID = entityID
			md = gosaml.Inflate([]byte(md))
			spMetaData = goxml.NewXp(md)
			res.Sp.Logo = spMetaData.Query1(nil, "md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Logo")
			res.Sp.RequestInitiators = spMetaData.QueryMulti(nil, "md:SPSSODescriptor/md:Extensions/init:RequestInitiator/@Location")
			res.Sp.DisplayNames = map[string]string{}
			for _, l := range []string{"en", "da"} {
				res.Sp.DisplayNames[l] = spMetaData.Query1(nil, "md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang='"+l+"']")
			}
			if res.Feds[0] == "" {
				res.Feds = spMetaData.QueryMulti(nil, "md:Extensions/wayf:wayf/wayf:feds")
			}
			res.DiscoResponse = spMetaData.QueryMulti(nil, "md:SPSSODescriptor/md:Extensions/idpdisc:DiscoveryResponse[@Binding='urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol']/@Location")
			res.DiscoACS = spMetaData.QueryMulti(nil, "md:SPSSODescriptor/md:AssertionConsumerService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']/@Location")
		}
	}

	res.Spok = (entityID == "") == (spMetaData == nil) // both either on or off

	if res.Spok {
		fedsquery := makeQuery(res.Feds, "feds:")
		if entityID != "" {
			chosenquery := makeQuery(chosen, "")

			// Find the still active earlier chosen IdPs - maybe they have gotten new displaynames
			res.Chosen, err = lookup("select json from disco where entityid MATCH ? limit 10", chosenquery)

			// Find if earlier chosen IdPs are relevant
			relevantIdPs, err := lookup("select json from disco where entityid MATCH ? limit 10", chosenquery+fedsquery+providerIDsquery)
			if err != nil {
				return err
			}

			for _, relevantIdP := range relevantIdPs {
				for i, chosen := range res.Chosen {
					if chosen.EntityID == relevantIdP.EntityID {
						res.Chosen[i].Relevant = true
					}
				}
			}

			prioritized, _ := lookup("select json from disco where keywords MATCH ? limit 10", fedsquery+" prioritized")
			for i, _ := range prioritized {
				prioritized[i].Relevant = true
			}
			res.Chosen = append(res.Chosen, prioritized...)
		}

		ftsquery = whitespace.ReplaceAllLiteralString(ftsquery, "* ")

		// Find number of relevant IdPs
		err = idpDB.QueryRow("select count(*) c from disco where keywords MATCH ?", ftsquery+fedsquery+providerIDsquery).Scan(&res.Found)
		if err != nil {
			return err
		}
		// Find the first 100 relevant IdPs
		res.Idps, err = lookup("select json from disco where keywords MATCH ? limit 100", ftsquery+fedsquery+providerIDsquery)
		if err != nil {
			return err
		}
		res.Rows = len(res.Idps)
	}
	b, err := json.Marshal(res)
	fmt.Fprintln(w, string(b))
	return
}

func lookup(query, params string) (res []idpInfoOut, err error) {
	rows, err := idpDB.Query(query, params)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var entityInfo []byte
		err = rows.Scan(&entityInfo)
		if err != nil {
			return
		}

		var f idpInfoIn
		x := idpInfoOut{DisplayNames: map[string]string{}}
		err = json.Unmarshal(entityInfo, &f)
		if err != nil {
			return
		}
		x.EntityID = f.EntityID
		//x.Keywords = keywords
		for _, dn := range f.DisplayNames {
			x.DisplayNames[dn.Lang] = dn.Value
		}

		res = append(res, x)
		//fmt.Fprintln(w, "f", f)
	}
	err = rows.Err()
	if err != nil {
		return
	}
	return
}

func makeQuery(vals []string, field string) (query string) {
    var delim string
	query = "("
	for _, val := range vals {
		val = notwordnorwhitespace.ReplaceAllLiteralString(val, "0")
		query += delim + field + val
		delim = " OR "
	}
	query += ")"
	return
}
