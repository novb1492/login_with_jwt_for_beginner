스프링 입문 후 jwt로그인 방식을 처음 구축해보는 초보자들을 위한 레포입니다<br/>
(This is a repo for beginners who are trying to build a jwt login method for the first time since they entered the spring)<br/>
<br/>

저 포함해 초보분들의 어려운 상황속 조금이라도 도움되는 정보길 희망합니다<br/>
(I hope it will help you with the difficult situations of beginners, including myself)<br/>
<br/>

사용법 <br/>
(how)
<br/>

스프링 2.대 버전이여서 openjdk 11 이상 받아서 하시면됩니다<br/>
(For your information, it's the Spring 2. version, so you can get an openjdk 11 or higher)<br/>
<br/>

redis를 설치합니다
(Install redis)<br/>

.proterties 파일은 없으나 리소스 폴더생성후 만드셔도 상관없습니다<br/>
(There is no .protecties file, but you can create it after creating a resource folder)<br/>
<br/>

토큰은 redis에 저장 되는 형식이므로 redis 설치후 포트번호는 6379가아니라면  Config폴더안 RedisConfig.java파일에서 포트를 바꾸면됩니다<br/>
(The token is stored in redis, so after installing redis, if the port number is not 6379, you can change the port in the Config folder RedisConfig.java file)<br/>
<br/>

그 외 별도의 설정을 필요없을걸로 예상됩니다<br/>
(Other than that, it is expected that there is no need for a separate setting)
<br/>

http://localhost:8080/login으로 post 요청 json형식으로 id: kim pwd:123 으로 요청하면 토큰을 얻을 수 있습니다<br/>
(Request post with http://localhost:8080/login You can get a token by requesting id: kimpwd:123 in json format)
<br/>

http://localhost:8080/pass/refresh 으로 post 요청 보내면 재발급 토큰 및 간단한 로그들을 볼 수 있을 겁니다<br/>
(If you send a post request to http://localhost:8080/pass/refresh, you will see reissue tokens and simple logs)
<br/>

저 포함해 초보분들의 어려운 상황속 조금이라도 도움되는 정보길 희망합니다<br/>
(I hope it will help you with the difficult situations of beginners, including myself)<br/>
<br/>

