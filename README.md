# 스프링 부트 초기 환경

- 스프링 부트 프로젝트 생성 : https://start.spring.io/
  : dependence ( Lombok, Spring Web, MyBatis Framework, PostgreSQL Driver )

- 정상 실행 확인
  > 테스트 레스트 확인 : http://localhost:8080, http://localhost:8080/greeting
  > http://localhost:8080/swagger-ui/index.html



# DB schema 생성
-  create schema test_scma authorization postgres;


# 참조 사이트

- token 관련
 -- 2개 참조 하여 만듬 
  https://blogan99.tistory.com/89
  https://adjh54.tistory.com/577 : springboot-01 샘플 


- acc token 기간만료 --> ref token 확인 후 ( acc 생성 후 전송, (클라이언트 처리는 ???) ), 리프레쉬 token 은 재 생성하지 않음(로그인 요청)

??? 먼저 테스트 완료 후 정보 얻어오느거 하기 ㅎㅎㅎ
