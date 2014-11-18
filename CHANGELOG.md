## [1.6.3]
Enhancements
* XssPreventer escape 오류 수정  

## [1.6.2]
Enhancements
* XssPreventer의 한글 데이터 unicode encoding 문제로 인해 apache-common-lang 3.3.2 적용 

## [1.6.1]
Enhancements
* IE Hack 내의 XSS 공격 취약점 수정

## [1.6.0]
New Features
* 파라미터로 받은 HTML 태그를 사내 보안팀 필수기준으로 escape/unescape 하는 API 추가

## [1.5.1]
Enhancements
* 메일 XSS 취약점 대응 - 화이트리스트 설정 파일에서 <blockingPrefix enable="true"> 를 사용하는 경우, 태그 폼이 살아있는 모든 Element(blockingPrefix 처리된 Element 포함)에 대해서 Attribute 필터링을 정상 태그와 동일한 수준 처리하도록 수정

## [1.5.0]
New Features
* HTML주석(<!-- 주석문 -->)내에 존재하는 element(HTML 태그)에 대한 필터링 설정 추가

## [1.4.0]
Enhancements
* attribute가 없는 element에 대해 removeAttrbute API 호출 시 NPE 발생에 대한 방어로직 추가

## [1.3.2]
Enhancements
* Embed, Object 태그에서 허용하는 확장자 및 type을 추가할 수 있는 확장포인트 제공 ( 3.4참고)

## [1.3.1]
Enhancements
* 카페 XSS 취약점 대응 - 따옴표 및 태그기호(<,>)의 비정상적인 사용으로 태그를 깨트려 XSS 공격을 하는 취약점 수정

## [1.3.0]
New Features
* Sax버전 필터에 char[]를 input으로 받는 doFilter API 를 추가함 (표 3 2 Lucy-XSS SaxFilter 주요 메소드참고)

Enhancements
* embed/object 관련 취약성 대응 - 화이트리스트 체크 및 type 속성 체크 및 추가를 통한 방어 
* DATA URI 관련 XSS 취약점 대응을 위해 src, data 속성에서 data: 문자열을 허용하지 않도록 함
* IE Hack 태그를 화이트리스트에 기본 포함 및 모든 태그에 올 수 있도록 수정
* 허용되지 않는 속성의 경우 필터링 시 지워지는데, 대상 속성값을 주석문에 표시하도록 해서 원본 값을 확인할 수 있도록 개선 

## [1.2.0]
New Features
* html5 지원
* 메모리 사용이 대폭 개선 된 SAX 방식의 필터 제공 (신규 사용자 및 메모리 이슈가 있는 서비스 사용 권장) 
* 특정 attribute가 disable 설정일 경우에도, 사용을 허용할 예외 태그리스트를 추가할 수 있는 속성 제공

Enhancements
* 동일한 설정 파일로 객체 생성 시 필터링 주석 On/Off 설정을 파라미터로 넘겨도 반영되지 않는 오류 수정
* DOM Parser 방식인 XssFilter의 메모리 사용량 개선(1.1.9 버전 대비 64%감소)
* %0b, %0c Hex코드를 이용한 XSS 공격 패턴을 방어할 수 있도록 개선
* attributeRule 에 notAllowedPattern과 allowedPattern이 동시에 사용될 경우 notAllowedPattern을 기본 적용 후 allowedPattern으로 예외 허용할 수 있도록 기능 개선
* 삭제 설정된 태그가 삭제될 경우, 삭제되었음을 알 수 있도록 태그 이름을 포함한 코멘트(<!-- Removed Tag Filtered -->) 추가
* getInstance() 호출 시 설정파일을 명시 안 하면 lucy-xss.xml 이 아닌 lucy-xss-superset.xml 보안설정을 사용하도록 변경
* SRC, DATA 속성에서 허용하는 패턴을 구체적으로 변경해서 공격 태그만 필터링되도록 설정 수정
* lucy-xss-default.xml의 FontStyle elementGroup에 center 태그 추가
* 화이트리스트 보안 설정 파일(lucy-xss-superset.xml)에 보안 검수 결과로 나온 신규 보안 설정 추가

## [1.1.9]
New Features
* Attribute에 대한 Listener 기능을 추가함
* 특정 Element 제거 기능을 추가함

Enhancements
* 공백이 들어가거나 endTag가 없는 IE 핵 태그에 대해서도 처리할 수 있도록 수정함
* 한글 이름을 갖는 태그는 태그가 아닌 텍스트로 인식하도록 예외 처리함

## [1.1.8]
New Features
* IE핵 태그를 description 이 아닌 Element를 상속한 IEHackExtensionElement로 인식할 수 있도록 개선함

Enhancements
* 비표준 IE 핵 태그를 표준 IE 핵 태그로 교정하도록 수정함

## [1.1.7]
New Features
* 특정 element의 모든 자식 콘텐츠를 삭제하는 element.removeAllContents() 메소드를 추가함

Enhancements
* child 설정 파일에서 기존 ElementGroup에 새로운 Element를 추가할 때, parent 설정 파일에서 정의한 Element 관계에 변경된 ElementGroup을 적용하도록 수정함
* 특정 element의 모든 속성을 삭제하는 element.removeAllAttributes() 메소드의 attribute가 없을 경우 Exception이 발생하던 문제 수정함
* description 파싱 룰(markup.rule)에 IE 핵 태그를 인식하도록 수정함


## [1.1.5]
New Features
* 공격패턴 검출 시 디버그를 위해 추가되는 주석문 표시 여부를 옵션으로 지정할 수 있도록 기능을 추가함

## [1.1.4]
New Features
* 공격패턴 XHTML 표준 준수 파싱 그래마 추가함
* Element API(removeAllAttributes, setName, setClose) 추가함
* ASCII Code %00 에 대한 파싱 그래마 추가함

## [1.1.3]
Enhancements
* junit 의존 scope를 test로 pom.xml 수정함

## [1.1.2]
New Features
* Base64Encoding XSS 공격 패턴 디코딩 로직을 추가함 
* lucy-xss-superset.xml 파일 공격 패턴 추가함
* Lucy-XSS-Superset XML File Update (lucy-xss-superset.xml)
* Base64Encoding XSS 공격 패턴 디코딩 대상 속성 추가 및 디코딩 설정

## [1.1.1]
Enhancements
* attribute value를 감쌀 수 있는 기존 규칙("", '')에 ``를 추가(markup.rule 수정) 함
