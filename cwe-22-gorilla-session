import go

// Query to detect potential path traversal vulnerabilities
from DataFlow::PathTraversal pt
where
  // Find calls to NewFilesystemStore where the second argument is derived from user-controlled input
  pt.getACall().getTarget().getName() = "sessions.NewFilesystemStore" and
  exists (Variable path | 
    // The path argument to NewFilesystemStore should be derived from user-controlled input
    pt.getAParameter().getAnArgument().getAnAccess().getBase().getACall().getQualifiedName() = "(*net/http.Request).Cookie" and
    pt.getAParameter() = path and
    path.asParameter().getType().(Type).getName() = "string" and
    // Look for tainted user input that reaches the path argument
    exists (Expr userInput |
      pt.getAParameter().getAnArgument().getAReachableExpression(userInput) and
      userInput instanceof IdentifierAccess
    )
  )
select pt, "Potential path traversal vulnerability"
