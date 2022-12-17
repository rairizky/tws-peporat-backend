import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:mysql1/mysql1.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart';
import 'package:shelf_router/shelf_router.dart';

// configure routes.
final _router = Router()
  ..post('/auth/login', _authLoginHandler)
  ..post('/auth/register', _authRegisterHandler)
  ..get('/reports', _getListReports)
  ..post('/reports', _postReport)
  ..patch('/reports', _patchReport)
  ..delete('/reports', _deleteReport)
  ..delete('/reports/hard-delete', _hardDeleteReport)
  ..get('/admin/reports', _getListAdminReports)
  ..patch('/admin/reports', _patchAdminReport);

//
// database connection
//
Future<MySqlConnection> connection() async {
  var settings = new ConnectionSettings(
      host: 'localhost',
      port: 8889,
      user: 'root',
      password: 'root',
      db: 'peporat_backend');
  var conn = await MySqlConnection.connect(settings);

  return conn;
}

//
// validate jwt
//
Future<Map> validateJWTUser(String token) async {
  var splitBearer = token.split(" ")[1];

  try {
    final verifyJWT = JWT.verify(splitBearer, SecretKey("peporat"));
    if (verifyJWT.payload.toString().contains("user")) {
      if (verifyJWT.payload["user"]["role"] == "USER") {
        return {...verifyJWT.payload, "error": false};
      }

      return {"error": true};
    }
  } on JWTError catch (_) {
    return {"error": true};
  }

  return {"error": true};
}

Future<Map> validateJWTAdmin(String token) async {
  var splitBearer = token.split(" ")[1];

  try {
    final verifyJWT = JWT.verify(splitBearer, SecretKey("peporat"));
    if (verifyJWT.payload.toString().contains("user")) {
      if (verifyJWT.payload["user"]["role"] == "ADMIN") {
        return {...verifyJWT.payload, "error": false};
      }

      return {"error": true};
    }
  } on JWTError catch (_) {
    return {"error": true};
  }

  return {"error": true};
}

//
// auth
//
Future<Response> _authLoginHandler(Request req) async {
  var conn = await connection();
  String bodyRequest = await req.readAsString();
  var data = json.decode(bodyRequest);

  var email = data["email"];
  var password = data["password"];

  var findEmail =
      await conn.query('SELECT * FROM users WHERE email = ?', [email]);

  if (findEmail.isNotEmpty) {
    var matchPassword = findEmail.first.fields["password"] ==
        md5.convert(utf8.encode(password)).toString();
    if (matchPassword) {
      final payload = JWT({"user": findEmail.first.fields});
      var token = payload.sign(SecretKey('peporat'));

      var user = {"user": findEmail.first.fields, "jwt": token};
      return Response.ok(user.toString());
    }

    return Response.unauthorized("Error: Password not match");
  }

  return Response.unauthorized("Error: Email not found");
}

Future<Response> _authRegisterHandler(Request req) async {
  var conn = await connection();
  String bodyRequest = await req.readAsString();
  var data = json.decode(bodyRequest);

  var name = data["name"];
  var email = data["email"];
  var password = data["password"];
  var role = "USER";

  var findEmail = await conn
      .query('SELECT * FROM users WHERE email = ? AND role = ?', [email, role]);

  if (findEmail.isEmpty) {
    var encryptedPassword = md5.convert(utf8.encode(password)).toString();

    await conn.query(
        "INSERT INTO users (name, email, password, role) VALUES (?,?,?,?)",
        [name, email, encryptedPassword, role]);

    return Response.ok("Create User Success");
  }

  return Response.unauthorized("Error: Email already exists");
}

//
// crud reports user
//
Future<Response> _getListReports(Request req) async {
  var token = req.headers["authorization"];
  var verifyJWT = await validateJWTUser(token.toString());
  if (verifyJWT["error"] == true) {
    return Response.unauthorized("Error: Unauthorized");
  }

  var conn = await connection();
  String bodyRequest = await req.readAsString();
  var data = json.decode(bodyRequest);

  var userId = verifyJWT["user"]["id"];

  var withDeleted = data["with_deleted"];
  if (withDeleted) {
    var reports = await conn.query(
        "SELECT * FROM reports WHERE deleted_at IS NOT NULL AND user_id = ? ORDER BY id DESC",
        [userId]);
    return Response.ok(reports.toString());
  }

  var reports = await conn.query(
      "SELECT * FROM reports WHERE deleted_at IS NULL AND user_id = ? ORDER BY id DESC",
      [userId]);

  return Response.ok(reports.toString());
}

Future<Response> _postReport(Request req) async {
  var token = req.headers["authorization"];
  var verifyJWT = await validateJWTUser(token.toString());
  if (verifyJWT["error"] == true) {
    return Response.unauthorized("Error: Unauthorized");
  }

  var conn = await connection();
  String bodyRequest = await req.readAsString();
  var data = json.decode(bodyRequest);

  var title = data["title"];
  var desc = data["description"];
  var reporter = data["reporter"];
  var status = "PENDING";
  var timestamp = DateTime.now().toString();
  var userId = verifyJWT["user"]["id"];

  await conn.query(
      "INSERT INTO reports (title, description, reporter, status, user_id, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
      [title, desc, reporter, status, userId, timestamp, timestamp]);

  return Response.ok("Create Report Success");
}

Future<Response> _patchReport(Request req) async {
  var token = req.headers["authorization"];
  var verifyJWT = await validateJWTUser(token.toString());
  if (verifyJWT["error"] == true) {
    return Response.unauthorized("Error: Unauthorized");
  }

  var conn = await connection();
  String bodyRequest = await req.readAsString();
  var data = json.decode(bodyRequest);

  var id = data["id"];
  var title = data["title"];
  var desc = data["description"];
  var reporter = data["reporter"];
  var timestamp = DateTime.now().toString();
  var userId = verifyJWT["user"]["id"];

  var findReport = await conn.query("SELECT * FROM reports WHERE id=?", [id]);
  if (findReport.isEmpty) {
    return Response.notFound("Error: Reports Not Found");
  }

  await conn.query(
      "UPDATE reports SET title=?, description=?, reporter=?, updated_at=? WHERE id=? AND user_id=?",
      [title, desc, reporter, timestamp, id, userId]);

  return Response.ok("Update Report Success");
}

Future<Response> _deleteReport(Request req) async {
  var token = req.headers["authorization"];
  var verifyJWT = await validateJWTUser(token.toString());
  if (verifyJWT["error"] == true) {
    return Response.unauthorized("Error: Unauthorized");
  }

  var conn = await connection();
  String bodyRequest = await req.readAsString();
  var data = json.decode(bodyRequest);

  var id = data["id"];
  var timestamp = DateTime.now().toString();
  var userId = verifyJWT["user"]["id"];

  var findReport = await conn
      .query("SELECT * FROM reports WHERE id=? AND user_id=?", [id, userId]);
  if (findReport.isEmpty) {
    return Response.notFound("Error: Reports Not Found");
  }

  await conn.query("UPDATE reports SET deleted_at=? WHERE id=? AND user_id=?",
      [timestamp, id, userId]);

  return Response.ok("Delete Report Success");
}

Future<Response> _hardDeleteReport(Request req) async {
  var token = req.headers["authorization"];
  var verifyJWT = await validateJWTUser(token.toString());
  if (verifyJWT["error"] == true) {
    return Response.unauthorized("Error: Unauthorized");
  }

  var conn = await connection();
  String bodyRequest = await req.readAsString();
  var data = json.decode(bodyRequest);

  var id = data["id"];
  var timestamp = DateTime.now().toString();
  var userId = verifyJWT["user"]["id"];

  var findReport = await conn
      .query("SELECT * FROM reports WHERE id=? AND user_id=?", [id, userId]);
  if (findReport.isEmpty) {
    return Response.notFound("Error: Reports Not Found");
  }

  await conn
      .query("DELETE FROM reports WHERE id=? AND user_id=?", [id, userId]);

  return Response.ok("Delete Report Success");
}

//
// data admin
//
Future<Response> _getListAdminReports(Request req) async {
  var token = req.headers["authorization"];
  var verifyJWT = await validateJWTAdmin(token.toString());
  if (verifyJWT["error"] == true) {
    return Response.unauthorized("Error: Unauthorized");
  }

  var conn = await connection();
  String bodyRequest = await req.readAsString();
  var data = json.decode(bodyRequest);

  var constantStatus = ["PENDING", "SURVEY", "PROCCESS", "FINISH"];

  var status = data["status"];
  print(status.toString().isNotEmpty);

  if (status.toString().isNotEmpty) {
    if (constantStatus.contains(status)) {
      var reports = await conn.query(
          "SELECT * FROM reports WHERE status=? AND deleted_at IS NULL ORDER BY id DESC",
          [status]);

      return Response.ok(reports.toString());
    }

    return Response.forbidden("Error: Status Not Match with Enum");
  }

  var reports = await conn
      .query("SELECT * FROM reports WHERE deleted_at IS NULL ORDER BY id DESC");

  return Response.ok(reports.toString());
}

Future<Response> _patchAdminReport(Request req) async {
  var token = req.headers["authorization"];
  var verifyJWT = await validateJWTAdmin(token.toString());
  if (verifyJWT["error"] == true) {
    return Response.unauthorized("Error: Unauthorized");
  }

  var conn = await connection();
  String bodyRequest = await req.readAsString();
  var data = json.decode(bodyRequest);

  var constantStatus = ["PENDING", "SURVEY", "PROCCESS", "FINISH"];

  var id = data["id"];
  var status = data["status"];
  var timestamp = DateTime.now().toString();

  var findReport = await conn.query("SELECT * FROM reports WHERE id=?", [id]);
  if (findReport.isEmpty) {
    return Response.notFound("Error: Reports Not Found");
  }

  if (constantStatus.contains(status)) {
    await conn.query("UPDATE reports SET status=?, updated_at=? WHERE id=?",
        [status, timestamp, id]);

    return Response.ok("Update Report Success");
  }

  return Response.forbidden("Error: Status Not Match with Enum");
}

void main(List<String> args) async {
  // Use any available host or container IP (usually `0.0.0.0`).
  final ip = InternetAddress.anyIPv4;

  // Configure a pipeline that logs requests.
  final handler = Pipeline().addMiddleware(logRequests()).addHandler(_router);

  // For running in containers, we respect the PORT environment variable.
  final port = int.parse(Platform.environment['PORT'] ?? '8080');
  final server = await serve(handler, ip, port);
  print('Server listening on port ${server.port}');
}
