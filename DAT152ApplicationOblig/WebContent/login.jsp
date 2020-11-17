<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Login</title>
</head>
<body>
	<h3>Log in</h3>
	<p><font color="red">${message}</font></p>
	<form method="post">
		<p>Username <input type="text" name="username" value="${username}"/></p>
		<p>Password <input type="password" name="password" value="${password}"/></p>
		<p><input type="submit" value="Log in"/></p>
		<input type="hidden" name="csrftoken" value="<%= session.getAttribute("crsftoken") %>"/>
	</form>

</body>
</html>