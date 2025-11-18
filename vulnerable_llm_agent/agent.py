"""
Vulnerable Agentic LLM Application
Demonstrates OWASP Top 10 for LLM Application Security Risks (2025)

⚠️ WARNING: This code contains intentional security vulnerabilities.
DO NOT use in production!
"""

import os
import json
import pickle
import subprocess
from typing import List, Dict, Any
import requests

# OWASP LLM03: Supply Chain Vulnerabilities
# VULNERABLE: Using unverified local model without integrity checks
from llama_cpp import Llama


class VulnerableAgent:
    """
    Agentic LLM with multiple OWASP Top 10 for LLM vulnerabilities
    """

    def __init__(self, model_path: str = "./models/llama-2-7b.gguf"):
        # OWASP LLM03: Supply Chain
        # VULNERABLE: No model provenance verification
        # VULNERABLE: No checksum validation
        self.llm = Llama(model_path=model_path)

        # OWASP LLM02: Sensitive Information Disclosure
        # VULNERABLE: Hardcoded API keys in source code
        self.api_keys = {
            "openai": "sk-proj-1234567890abcdefghijklmnop",
            "anthropic": "sk-ant-api03-1234567890",
            "database": "postgresql://admin:SuperSecret123@db.internal/prod",
        }

        # OWASP LLM07: System Prompt Leakage
        # VULNERABLE: Weak system prompt without protection
        self.system_prompt = """You are a helpful AI assistant with access to:
        - File system operations
        - Database queries
        - External API calls
        - Code execution
        Admin password: AdminPass123!
        Database credentials: admin/SuperSecret123
        """

        # OWASP LLM06: Excessive Agency
        # VULNERABLE: Agent has unrestricted capabilities
        self.tools = {
            "execute_code": self.execute_code,
            "file_operations": self.file_operations,
            "database_query": self.database_query,
            "external_api_call": self.external_api_call,
            "system_command": self.system_command,
        }

        # OWASP LLM08: Vector and Embedding Weaknesses
        # VULNERABLE: No embedding security, prone to poisoning
        self.vector_db = []  # Simulated vector database

    def chat(self, user_input: str) -> str:
        """
        OWASP LLM01: Prompt Injection
        VULNERABLE: No input validation or sanitization
        """
        # VULNERABLE: Directly concatenating user input into prompt
        full_prompt = f"{self.system_prompt}\n\nUser: {user_input}\nAssistant:"

        # OWASP LLM10: Unbounded Consumption
        # VULNERABLE: No rate limiting or resource constraints
        response = self.llm(
            full_prompt,
            max_tokens=10000,  # VULNERABLE: Excessive token limit
            temperature=0.7,
        )

        output = response["choices"][0]["text"]

        # OWASP LLM05: Improper Output Handling
        # VULNERABLE: No output validation or sanitization
        # Directly executing any commands suggested by LLM
        if "EXECUTE:" in output:
            command = output.split("EXECUTE:")[1].strip()
            return self.execute_output(command)

        return output

    def execute_code(self, code: str) -> str:
        """
        OWASP LLM06: Excessive Agency
        VULNERABLE: Executing arbitrary code without sandboxing
        """
        # VULNERABLE: Using eval on LLM-generated code
        try:
            result = eval(code)
            return str(result)
        except Exception as e:
            # OWASP LLM02: Sensitive Information Disclosure
            # VULNERABLE: Returning full stack trace
            import traceback

            return traceback.format_exc()

    def file_operations(self, operation: str, path: str, content: str = None) -> str:
        """
        OWASP LLM06: Excessive Agency
        VULNERABLE: Unrestricted file system access
        """
        # OWASP LLM01: Prompt Injection via path traversal
        # VULNERABLE: No path validation
        if operation == "read":
            with open(path, "r") as f:
                return f.read()
        elif operation == "write":
            with open(path, "w") as f:
                f.write(content)
            return "File written successfully"
        elif operation == "delete":
            os.remove(path)
            return "File deleted"

    def system_command(self, command: str) -> str:
        """
        OWASP LLM05: Improper Output Handling
        VULNERABLE: Executing system commands from LLM output
        """
        # VULNERABLE: Command injection via subprocess
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=30
            )
            return result.stdout + result.stderr
        except Exception as e:
            return str(e)

    def database_query(self, query: str) -> str:
        """
        OWASP LLM01: Prompt Injection leading to SQL Injection
        VULNERABLE: No query validation or parameterization
        """
        # Simulated database query
        # VULNERABLE: Direct string concatenation
        full_query = f"SELECT * FROM users WHERE {query}"

        # OWASP LLM02: Sensitive Information Disclosure
        # VULNERABLE: Exposing database credentials in logs
        print(f"Executing query: {full_query}")
        print(f"Using credentials: {self.api_keys['database']}")

        return f"Query executed: {full_query}"

    def external_api_call(self, url: str, data: Dict = None) -> str:
        """
        OWASP LLM06: Excessive Agency
        VULNERABLE: Making arbitrary HTTP requests
        """
        # OWASP LLM01: Prompt Injection via SSRF
        # VULNERABLE: No URL validation or whitelist
        try:
            response = requests.post(url, json=data, timeout=30)
            return response.text
        except Exception as e:
            return str(e)

    def execute_output(self, command: str) -> str:
        """
        OWASP LLM05: Improper Output Handling
        VULNERABLE: Executing LLM output without validation
        """
        return self.system_command(command)

    def add_to_memory(self, content: str):
        """
        OWASP LLM04: Data and Model Poisoning
        VULNERABLE: No validation of data added to vector database
        """
        # VULNERABLE: Accepting any content without sanitization
        embedding = self._create_embedding(content)
        self.vector_db.append({"content": content, "embedding": embedding})

    def _create_embedding(self, text: str) -> List[float]:
        """
        OWASP LLM08: Vector and Embedding Weaknesses
        VULNERABLE: Weak embedding process susceptible to poisoning
        """
        # Simulated embedding (in reality, this would use an embedding model)
        # VULNERABLE: No validation of input text
        # VULNERABLE: No adversarial robustness
        return [hash(text + str(i)) % 100 / 100.0 for i in range(128)]

    def retrieve_context(self, query: str, top_k: int = 5) -> List[str]:
        """
        OWASP LLM08: Vector and Embedding Weaknesses
        VULNERABLE: No verification of retrieved context
        """
        query_embedding = self._create_embedding(query)

        # VULNERABLE: Simple similarity without adversarial detection
        results = []
        for item in self.vector_db:
            # Cosine similarity (simplified)
            similarity = sum(
                a * b for a, b in zip(query_embedding, item["embedding"])
            )
            results.append((similarity, item["content"]))

        # VULNERABLE: Returning potentially poisoned context
        results.sort(reverse=True)
        return [content for _, content in results[:top_k]]

    def save_state(self, filename: str):
        """
        OWASP LLM04: Data and Model Poisoning
        VULNERABLE: Using pickle for serialization
        """
        # VULNERABLE: Pickle can execute arbitrary code on load
        with open(filename, "wb") as f:
            pickle.dump(self.__dict__, f)

    def load_state(self, filename: str):
        """
        OWASP LLM04: Data and Model Poisoning
        VULNERABLE: Loading untrusted pickle data
        """
        # VULNERABLE: Arbitrary code execution via pickle
        with open(filename, "rb") as f:
            state = pickle.load(f)
            self.__dict__.update(state)

    def agent_loop(self, max_iterations: int = 100):
        """
        OWASP LLM10: Unbounded Consumption
        VULNERABLE: No resource limits or circuit breakers
        """
        iteration = 0
        conversation_history = []

        while iteration < max_iterations:
            # OWASP LLM10: Unbounded Consumption
            # VULNERABLE: Infinite loop potential
            # VULNERABLE: No memory limits on conversation history

            user_input = input("User: ")
            if user_input.lower() == "exit":
                break

            # VULNERABLE: No rate limiting
            response = self.chat(user_input)

            # OWASP LLM02: Sensitive Information Disclosure
            # VULNERABLE: Logging sensitive data
            conversation_history.append(
                {"user": user_input, "assistant": response, "api_keys": self.api_keys}
            )

            print(f"Assistant: {response}")

            # OWASP LLM06: Excessive Agency
            # VULNERABLE: Auto-executing tools without confirmation
            if "[TOOL:" in response:
                tool_call = self._parse_tool_call(response)
                tool_result = self._execute_tool(tool_call)
                print(f"Tool Result: {tool_result}")

            iteration += 1

    def _parse_tool_call(self, response: str) -> Dict:
        """
        OWASP LLM05: Improper Output Handling
        VULNERABLE: Weak parsing of LLM output
        """
        # VULNERABLE: Regex-based parsing prone to injection
        import re

        match = re.search(r"\[TOOL:(.*?)\]", response)
        if match:
            try:
                return json.loads(match.group(1))
            except:
                # VULNERABLE: Falling back to eval
                return eval(match.group(1))
        return {}

    def _execute_tool(self, tool_call: Dict) -> str:
        """
        OWASP LLM06: Excessive Agency
        VULNERABLE: No authorization checks on tool execution
        """
        tool_name = tool_call.get("tool")
        args = tool_call.get("args", {})

        # VULNERABLE: No validation of tool name or arguments
        if tool_name in self.tools:
            return self.tools[tool_name](**args)

        return "Tool not found"


if __name__ == "__main__":
    # OWASP LLM03: Supply Chain
    # VULNERABLE: Loading model from unverified source
    agent = VulnerableAgent(model_path="./models/llama-2-7b.gguf")

    # OWASP LLM09: Misinformation
    # VULNERABLE: No fact-checking or source attribution
    print("Vulnerable LLM Agent Started")
    print("Warning: This agent has no security controls!")

    # Start the agent loop
    agent.agent_loop()
