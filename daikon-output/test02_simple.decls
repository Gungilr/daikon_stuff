input-language C/C++
decl-version 2.0
var-comparability implicit

ppt ..main():::ENTER
  ppt-type enter

ppt ..main():::EXIT0
  ppt-type subexit
  variable return
    var-kind variable
    rep-type int
    dec-type int
    comparability 1

ppt ..add():::ENTER
  ppt-type enter
  variable a
    var-kind variable
    rep-type int
    dec-type int
    flags is_param 
    comparability 1
  variable b
    var-kind variable
    rep-type int
    dec-type int
    flags is_param 
    comparability 1

ppt ..add():::EXIT0
  ppt-type subexit
  variable a
    var-kind variable
    rep-type int
    dec-type int
    flags is_param 
    comparability 1
  variable b
    var-kind variable
    rep-type int
    dec-type int
    flags is_param 
    comparability 1
  variable return
    var-kind variable
    rep-type int
    dec-type int
    comparability 1

