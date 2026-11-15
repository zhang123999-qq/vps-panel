package sshx

import "testing"

func TestPrivilegeWrap(t *testing.T) {
	root := Privilege{User: "root", IsRoot: true}
	if got := root.Wrap("systemctl restart x"); got != "systemctl restart x" {
		t.Errorf("root 不应加 sudo: %q", got)
	}
	user := Privilege{User: "next", IsRoot: false, Sudo: true}
	if got := user.Wrap("systemctl restart x"); got != "sudo -n systemctl restart x" {
		t.Errorf("非 root 应加 sudo -n: %q", got)
	}
}

func TestPrivilegeCheck(t *testing.T) {
	if err := (Privilege{IsRoot: true}).Check(); err != nil {
		t.Errorf("root 应通过: %v", err)
	}
	if err := (Privilege{User: "next", Sudo: true}).Check(); err != nil {
		t.Errorf("免密 sudo 应通过: %v", err)
	}
	err := (Privilege{User: "next"}).Check()
	if err == nil {
		t.Fatal("非 root 且无 sudo 必须报错")
	}
	for _, want := range []string{"next", "root", "sudo"} {
		if !contains(err.Error(), want) {
			t.Errorf("错误信息应包含 %q: %s", want, err.Error())
		}
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"sudo: a terminal is required to read the password":               "sudo",
		"sudo: a password is required":                                    "sudo",
		"cp: cannot create regular file: Permission denied":               "权限不足",
		"/tmp/xray_upload: cannot execute binary file: Exec format error": "Exec format error",
		"bash: xray: command not found":                                   "command not found",
		"No space left on device":                                         "磁盘已满",
		"Text file busy":                                                  "占用",
		"Read-only file system":                                           "只读",
		"":                                                                "",
	}
	for in, want := range cases {
		got := Classify(in)
		if want == "" {
			if got != "" {
				t.Errorf("空输出不应归类，实际 %q", got)
			}
			continue
		}
		if !contains(got, want) {
			t.Errorf("Classify(%q)=%q，应包含 %q", in, got, want)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
