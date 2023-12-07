package api

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/acoshift/arpc/v2"
)

type Empty struct{}

func (*Empty) UnmarshalRequest(r *http.Request) error {
	if r.Method != http.MethodGet {
		return arpc.ErrUnsupported
	}
	return nil
}

func (*Empty) Table() [][]string {
	return [][]string{{"Operation success"}}
}

type ID int64

func (id ID) Int64() int64 {
	return int64(id)
}

func (id ID) Value() (driver.Value, error) {
	return int64(id), nil
}

func (id ID) String() string {
	return strconv.FormatInt(int64(id), 10)
}

func (id ID) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.String())
}

func (id *ID) UnmarshalJSON(b []byte) error {
	*id = 0

	if len(b) == 0 {
		return nil
	}

	if b[0] == '"' {
		var s string
		err := json.Unmarshal(b, &s)
		if err != nil {
			return err
		}
		if s == "" {
			return nil
		}
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return err
		}
		*id = ID(i)
		return nil
	}

	var i int64
	err := json.Unmarshal(b, &i)
	if err != nil {
		return err
	}
	*id = ID(i)
	return nil
}

func Int(i int) *int {
	return &i
}

func Int64(i int64) *int64 {
	return &i
}

func String(s string) *string {
	return &s
}

func Bool(b bool) *bool {
	return &b
}

func age(t time.Time) string {
	d := time.Since(t)
	if x := d / (24 * time.Hour); x > 0 {
		return fmt.Sprintf("%dd", x)
	}
	if x := d / (24 * time.Hour); x > 0 {
		return fmt.Sprintf("%dh", x)
	}
	if x := d / time.Minute; x > 0 {
		return fmt.Sprintf("%dm", x)
	}
	return fmt.Sprintf("%ds", d/time.Second)
}
