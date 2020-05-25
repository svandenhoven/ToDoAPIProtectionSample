/*
 The MIT License (MIT)

Copyright (c) 2018 Microsoft Corporation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using TodoListService.Models;

namespace TodoListService.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    public class TodoListController : Controller
    {
        // In-memory TodoList
        private static readonly Dictionary<int, Todo> TodoStore = new Dictionary<int, Todo>();

        private readonly IHttpContextAccessor _contextAccessor;

        public TodoListController(IHttpContextAccessor contextAccessor)
        {
            this._contextAccessor = contextAccessor;

            // Pre-populate with sample data
            if (TodoStore.Count == 0)
            {
                TodoStore.Add(1, new Todo() { Id = 1, Owner = $"{this._contextAccessor.HttpContext.User.Identity.Name}", Title = "Pick up groceries" });
                TodoStore.Add(2, new Todo() { Id = 2, Owner = $"{this._contextAccessor.HttpContext.User.Identity.Name}", Title = "Finish invoice report" });
            }
        }

        // GET: api/values
        [HttpGet]
        [Authorize]
        public ActionResult<IEnumerable<Todo>> Get()
        {
            //Check the Scope in the Access_Token
            string[] scopes = null;
            
            var scpClaims = User.Claims.Where(c => c.Type == "scp");
            var roleClaims = User.Claims.Where(c => c.Type == "roles");

            if (scpClaims.Count() > 0)
                scopes = scpClaims.FirstOrDefault().Value.Split(" ");

            if (scopes == null || !scopes.Contains("ToDo.Read"))
            {
                if (User.IsInRole("Todo.Read.All"))
                {
                    //The call is with application permissions
                    return Ok(TodoStore.Values);

                }
                else
                {
                    return Forbid();
                }
            }

            //Return only the items from the user in the Access_Token
            string owner = User.Identity.Name;
            var oidClaims = User.Claims.Where(c => c.Type == "oid");
            if (oidClaims.Count() > 0)
                owner = oidClaims.FirstOrDefault().Value;

            return Ok(TodoStore.Values.Where(x => x.Owner == owner));
        }

        // GET: api/values
        [HttpGet("{id}", Name = "Get")]
        public ActionResult<Todo> Get(int id)
        {
            //get scopes from token
            string[] scopes = null;
            var scpClaims = User.Claims.Where(c => c.Type == "scp");
            if (scpClaims.Count() > 0)
                scopes = scpClaims.FirstOrDefault().Value.Split(" ");

            if (scopes.Contains("ToDo.Read"))
            {
                // accesstoken has ToDo.Read scope
                string owner = User.Identity.Name;
                var oidClaims = User.Claims.Where(c => c.Type == "oid");
                if (oidClaims.Count() > 0)
                    owner = oidClaims.FirstOrDefault().Value;

                //Validate that only Id from current user is returned
                return TodoStore.Values.FirstOrDefault(t => t.Id == id && t.Owner == owner);
            }
            else
            {
                // accesstoken does not have ToDo.Read scope
                return Forbid();
            }
        }

        [HttpDelete("{id}")]
        [Authorize(Policy = "ToDo.Write")]
        public ActionResult Delete(int id)
        {
            var owner = GetOid();

            var todo = TodoStore.Values.FirstOrDefault(x => x.Id == id);
            if (todo != null)
            {
                if (todo.Owner == owner)
                {
                    TodoStore.Remove(id);
                }
                else
                    return Unauthorized();
            }
            return Ok();
        }

        private string GetOid()
        {
            string owner = null;
            var oidClaims = User.Claims.Where(c => c.Type == "oid");
            if (oidClaims.Count() > 0)
                owner = oidClaims.FirstOrDefault().Value;
            return owner;
        }

        // POST api/values
        [HttpPost]
        [Authorize(Policy = "ToDo.Write")]
        public IActionResult Post([FromBody] Todo todo)
        {
            string owner = User.Identity.Name;
            var oidClaims = User.Claims.Where(c => c.Type == "oid");
            if (oidClaims.Count() > 0)
                owner = oidClaims.FirstOrDefault().Value;

            int id = TodoStore.Values.OrderByDescending(x => x.Id).FirstOrDefault().Id + 1;
            Todo todonew = new Todo() { Id = id, Owner = owner, Title = todo.Title };
            TodoStore.Add(id, todonew);

            return Ok(todo);
        }

        // PATCH api/values
        [HttpPatch("{id}")]
        [Authorize(Policy = "ToDo.Read")]
        public IActionResult Patch(int id, [FromBody] Todo todo)
        {
            if (id != todo.Id)
            {
                return NotFound();
            }

            if (TodoStore.Values.FirstOrDefault(x => x.Id == id) == null)
            {
                return NotFound();
            }

            TodoStore.Remove(id);
            TodoStore.Add(id, todo);

            return Ok(todo);
        }
    }
}