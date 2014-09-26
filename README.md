## Lucy-XSS
Lucy-XSS(Cross Site Scripting)는 악의적인 XSS 코드의 위험으로부터 웹 애플리케이션을 보호하는 두 가지 방식의 방어 라이브러리를 제공한다.

## XssFilter : 화이트리스트(White List) 설정 방식으로 구현한 Java 기반의 필터 라이브러리
Lucy-XSS(Cross Site Scripting) Filter는 악의적인 XSS 코드의 위험으로부터 웹 애플리케이션을 보호하는 기능을 화이트리스트(White List) 설정 방식으로 구현한 
Java 기반의 필터 라이브러리이다. Lucy-XSS Filter를 사용하여 전사 표준 XSS 관련 보안 정책을 적용할 수 있으며, 블랙리스트 방식을 사용하는 기존 필터보다 안전하게 
웹 서비스를 제공할 수 있다.

![Lucy-XSS Filter structure.jpg](/files/18411)
Lucy-XSS Filter 객체를 생성하면 Configuration Builder는 White List Configuration에 정의된 내용을 바탕으로 White List Object Model을 생성하여 
Lucy-XSS Filter Core로 전달한다. Lucy-XSS Filter Core는 Markup Parser(DOM, SAX 둘 다 지원 )가 필터링 대상 HTML 문자열을 파싱하여 생성한 HTML Object Model을 
White List Object Model과 비교하여 필터링한다.

## XssPreventer : 파라미터 문자열을 변환하는 apache-common-lang 기반의 라이브러리
악의적인 XSS 코드의 위험으로부터 웹 애플리케이션을 보호하는 apache-common-lang기반의 라이브러리이다. 
Lucy-XSS Filter와의 차이점은 Lucy-XSS Preventer는 파라미터가 HTML 태그로 인식할 수 없도록 모든 문자열을 단순 변환하고 
Lucy-XSS Filter는 White List 방식으로 허용한 HTML은 필터링하지 않는다는 차이가 있다.



## Getting started



## Usage examples



## Contributing to Lucy



## Licensing
Lucy is licensed under the Apache License, Version 2.0. See LICENSE for full license text.
