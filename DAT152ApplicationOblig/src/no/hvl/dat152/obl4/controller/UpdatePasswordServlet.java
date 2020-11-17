package no.hvl.dat152.obl4.controller;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import no.hvl.dat152.obl4.database.AppUser;
import no.hvl.dat152.obl4.database.AppUserDAO;
import no.hvl.dat152.obl4.util.Validator;

@WebServlet("/updatepassword")
public class UpdatePasswordServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		// request.getRequestDispatcher("updatepassword.jsp").forward(request,
		// response);
		doPost(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		request.removeAttribute("message");

		boolean successfulPasswordUpdate = false;

		String passwordnew = Validator.validString(request.getParameter("passwordnew"));
		String confirmedPasswordnew = Validator.validString(request.getParameter("confirm_passwordnew"));

		if (RequestHelper.isLoggedIn(request)) {

			AppUser user = (AppUser) request.getSession().getAttribute("user");

			AppUserDAO userDAO = new AppUserDAO();

			if (passwordnew.equals(confirmedPasswordnew)) {
				if (Validator.validPassword(passwordnew)) {

					successfulPasswordUpdate = userDAO.updateUserPassword(user.getUsername(), passwordnew);
				} else {
					request.setAttribute("message", "Password too short!");
					request.getRequestDispatcher("updatepassword.jsp").forward(request, response);
				}

				if (successfulPasswordUpdate) {

					response.sendRedirect("mydetails");

				} else {
					request.setAttribute("message", "Password update failed!");
					request.getRequestDispatcher("updatepassword.jsp").forward(request, response);
				}
			}

		} else {
			request.getSession().invalidate();
			request.getRequestDispatcher("index.html").forward(request, response);
		}

	}

}
