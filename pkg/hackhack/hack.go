package hack

var stall bool

func Stall() {
	stall = true
}

func ShouldStall() bool {
	return (stall == true)
}
