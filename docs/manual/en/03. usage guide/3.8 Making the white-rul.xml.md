## white-url 작성
“white-url.xml” 파일이 없거나, “white-url.xml“에 기술되지 않은 모든 리소스는 ObjectListener/EmbedListener에 의해 보안설정이 추가되거나 보안상 위험 할 경우 disable 처리가 될 수 있으므로, Object, Embed 태그 사용 시 안전한 url 패턴에 대해서는 “white-url.xml“ 파일에 등록을 권장한다. Devcode에서 다운로드 한 “white-url.xml”을 참고하여 아래 형태로 작성한다.

아래 설정에서 <domain> 태그는 생략 가능하다.

```xml
<?xml version="1.0" encoding="UTF-8"?>

<white-url>
    <domain name="http://www.naver.com" desc="네이버">
        <pattern>http://serviceapi.nmv.naver.com/*</pattern>
        <pattern>http://scrap.ad.naver.com/*</pattern>
    </domain>
    <domain name="http://www.daum.net" desc="다음">
        <pattern>http://flvs.daum.net/flvPlayer.swf*</pattern>
    </domain>

    ...

</white-url>
```

> Object, Embed 태그를 사용하지 않는 서비스 부서에서는 white-url.xml 작성을 생략해도 된다.