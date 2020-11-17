<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
    <%@ page import="no.hvl.dat152.obl4.dictionary.DictionaryDAO" %>
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>New User</title>
</head>
<body>
	<h3>Register new user</h3>
	<p><font color="red">${message}</font></p>
	<form method="post">
		<p>Username <input type="text" name="username" /></p>
		<p>Password <input type="password" name="password" /></p>
		<p>Confirm Password <input type="password" name="confirm_password" /></p>
		<p>First Name <input type="text" name="first_name" /></p>
		<p>Last Name <input type="text" name="last_name" /></p>
		<p>Mobile Phone <input type="text" name="mobile_phone" /></p>
		<p><b>Preferred Dictionary Source for this computer</b><br>
			<input type="radio" name="dicturl" 
				value="<%=DictionaryDAO.DEFAULT_DICT_URL %>"
				 checked="checked"/>
				http://localhost... (Norway)<br>
			<input type="radio" name="dicturl" 
				value="http://www.mso.anu.edu.au/~ralph/OPTED/v003/"/>
				http://www.mso.anu.edu.au... (Australia)
		<p><input type="submit" value="Register and log in"/></p>
		<input type="hidden" name="csrftoken" value="<%= session.getAttribute("crsftoken") %>"/>
	</form>

</body>
</html>