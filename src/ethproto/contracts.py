import os
import time
from contextlib import contextmanager
from decimal import Decimal
from functools import wraps

from environs import Env
from m9g import Model
from m9g.fields import DictField, IntField, ListField, StringField, TupleField

from .wadray import Ray, Wad

__author__ = "Guillermo M. Narvaja"
__copyright__ = "Guillermo M. Narvaja"
__license__ = "MIT"

env = Env()

USE_CUSTOM_ERRORS = env.bool("USE_CUSTOM_ERRORS", False)


class RevertError(Exception):
    pass


class RevertCustomError(RevertError):
    def __init__(self, error, *args):
        self.error = error
        self.args = args

    def __str__(self):
        return f"{self.error}({', '.join(map(str, self.args))})"


class WadField(IntField):
    FIELD_TYPE = Wad

    def adapt(self, value):
        if type(value) in (str, float, Decimal, int):
            return Wad.from_value(value)
        elif isinstance(value, Wad):
            return value
        raise ValueError("Invalid value")


class RayField(IntField):
    FIELD_TYPE = Ray

    def adapt(self, value):
        if type(value) in (str, float, Decimal, int):
            return Ray.from_value(value)
        elif isinstance(value, Ray):
            return value
        raise ValueError("Invalid value")


class AddressField(StringField):
    pass


class ContractProxy(str):
    def _get_contract(self):
        return Contract.manager.findByPrimaryKey(self)

    def __getattr__(self, attr_name):
        return getattr(self._get_contract(), attr_name)

    def __setattr__(self, attr_name, attr_value):
        return setattr(self._get_contract(), attr_name, attr_value)


class ContractProxyField(AddressField):
    FIELD_TYPE = ContractProxy

    def adapt(self, value):
        if type(value) == str:
            return ContractProxy(value)
        elif value is None:
            return None
        elif isinstance(value, ContractProxy):
            return value
        elif isinstance(value, Contract):
            return ContractProxy(value.contract_id)
        raise ValueError("Invalid value")


_current_transaction = None


class RWTransaction:
    def __init__(self):
        self.modified_contract_ids = set()
        self.modified_contracts = []
        self.track_count = 0

    @contextmanager
    def track(self, contract):
        if contract.contract_id not in self.modified_contract_ids:
            self.modified_contract_ids.add(contract.contract_id)
            self.modified_contracts.append(contract)
            contract.push_version()
        self.track_count += 1
        try:
            yield self
        except RevertError:
            self.track_count -= 1
            if self.track_count == 0:
                self.archive()
                self._on_revert()
            raise
        except Exception:
            self.track_count -= 1
            if self.track_count == 0:
                self.archive()
            raise
        else:
            self.track_count -= 1
            if self.track_count == 0:
                self.archive()
                self._on_end()

    def _on_revert(self):
        while self.modified_contracts:
            contract = self.modified_contracts.pop()
            self.modified_contract_ids.remove(contract.contract_id)
            contract.pop_version()

    def _on_end(self):
        pass

    def archive(self):
        "Archives the transaction - No longer current transaction"
        global _current_transaction
        _current_transaction = None
        # TODO: keep transaction somewhere to track events for example


class ROTransaction:
    def __init__(self):
        self.modified_contracts = []
        self.serialized_contracts = {}
        self.track_count = 0

    @contextmanager
    def track(self, contract):
        if contract.contract_id not in self.serialized_contracts:
            self.serialized_contracts[contract.contract_id] = contract.serialize("pydict")
            self.modified_contracts.append(contract)
        self.track_count += 1
        try:
            yield self
        finally:
            self.track_count -= 1
            if self.track_count == 0:
                self.archive()
                self._on_end()

    def _on_end(self):
        while self.modified_contracts:
            contract = self.modified_contracts.pop()
            assert (
                contract.serialize("pydict") == self.serialized_contracts[contract.contract_id]
            ), f"Contract {contract.contract_id} modified in view"
            del self.serialized_contracts[contract.contract_id]

    def archive(self):
        "Archives the transaction - No longer current transaction"
        global _current_transaction
        _current_transaction = None
        # TODO: keep transaction somewhere to track events for example


def external(method):
    if os.environ.get("DISABLE_EXTERNAL", None) == "T":
        return method

    @wraps(method)
    def rollback_on_error(self, *args, **kwargs):
        global _current_transaction
        if _current_transaction is None:
            _current_transaction = RWTransaction()
        elif isinstance(_current_transaction, ROTransaction):
            raise RuntimeError("Calling external from view")

        with _current_transaction.track(self):
            return method(self, *args, **kwargs)

    return rollback_on_error


def view(method):
    if os.environ.get("DISABLE_EXTERNAL", None) == "T":
        return method

    @wraps(method)
    def verify_unchanged(self, *args, **kwargs):
        global _current_transaction
        if _current_transaction is None:
            _current_transaction = ROTransaction()

        with _current_transaction.track(self):
            return method(self, *args, **kwargs)

    return verify_unchanged


def only_role(*roles):
    def decorator(method):
        @wraps(method)
        def inner(self, *args, **kwargs):
            for role in roles:
                if self.has_role(role, self.running_as):
                    break
            else:
                self._error("AccessControlUnauthorizedAccount", self.running_as, role)
            return method(self, *args, **kwargs)

        return inner

    return decorator


class ContractManager:
    def __init__(self):
        self._contracts = {}

    def add_contract(self, pk, contract):
        self._contracts[pk] = contract

    def findByPrimaryKey(self, pk):
        return self._contracts[pk]

    def clean_all(self):
        self._contracts = {}


class Contract(Model):
    version_format = "pydict"
    max_versions = 10
    contract_id = StringField(pk=True)

    manager = ContractManager()

    def __init__(self, contract_id=None, **kwargs):
        if contract_id is None:
            contract_id = f"{self.__class__.__name__}-{id(self)}"
        self.use_custom_errors = kwargs.pop("use_custom_errors", USE_CUSTOM_ERRORS)
        super().__init__(contract_id=contract_id, **kwargs)
        self._versions = []
        self.manager.add_contract(self.contract_id, self)

    def _error(self, error_class, *args) -> RevertError:
        return RevertCustomError(error_class, *args)

    @contextmanager
    def as_(self, user):
        "Dummy as method to do the same with the wrapper"
        prev_running_as = getattr(self, "_running_as", "missing")
        self._running_as = user
        try:
            yield self
        finally:
            if prev_running_as == "missing":
                del self._running_as
            else:
                self._running_as = prev_running_as

    @property
    def running_as(self):
        return getattr(self, "_running_as", None)

    def push_version(self, version_name=None):
        if version_name is None:
            version_name = "v%.3f" % time.time()
        serialized = self.serialize(self.version_format)
        if not hasattr(self, "_versions"):
            self._versions = [(serialized, version_name)]
        else:
            self._versions.append((serialized, version_name))
        if len(self._versions) > self.max_versions:
            self._versions.pop(0)

    def pop_version(self, version_name=None):
        if version_name is None:
            serialized, _ = self._versions.pop()
        else:
            version_index = [i for i, (_, v) in enumerate(self._versions) if v == version_name]
            serialized, _ = self._versions.pop(version_index[0])
        self.in_place_deserialize(serialized, format=self.version_format)


class AccessControlContract(Contract):
    owner = AddressField(default="owner")
    roles = DictField(StringField(), TupleField((ListField(AddressField()), StringField())), default={})

    set_attr_roles = {}

    # struct RoleData {
    #    mapping (address => bool) members;
    #    bytes32 adminRole;
    # }
    # mapping (bytes32 => RoleData) private _roles;

    # function hasRole(bytes32 role, address account) external view returns (bool);
    # function getRoleAdmin(bytes32 role) external view returns (bytes32); - TODO
    # function grantRole(bytes32 role, address account) external;
    # function revokeRole(bytes32 role, address account) external; - TODO
    # function renounceRole(bytes32 role, address account) external; - TODO

    def __init__(self, **kwargs):
        with self._disable_role_validation():
            super().__init__(**kwargs)
            self._running_as = self.owner
            self.roles[""] = ([self.owner], "")  # Add owner as default_admin

    def _error(self, error_class, *args) -> RevertError:
        if error_class == "AccessControlUnauthorizedAccount":
            if self.use_custom_errors:
                return RevertCustomError(error_class, args[0], args[1])
            else:
                return RevertError(f"AccessControl: account {args[0]} is missing role {args[1]}")
        return super()._error(error_class, *args)

    @contextmanager
    def _disable_role_validation(self):
        self._role_validation_disabled = True
        try:
            yield self
        finally:
            del self._role_validation_disabled

    def pop_version(self, *args, **kwargs):
        with self._disable_role_validation():
            super().pop_version(*args, **kwargs)

    def has_role(self, role, account):
        members = self.roles.get(role, ((), ""))[0]
        return account in members

    def grant_role(self, role, user):
        "Dummy as method to do the same with the wrapper"
        if role in self.roles:
            members, admin_role = self.roles[role]
        else:
            members, admin_role = [], ""
        require(
            self.has_role(admin_role, self._running_as),
            self._error("AccessControlUnauthorizedAccount", self._running_as, admin_role),
        )

        if user not in members:
            members.append(user)
        self.roles[role] = (members, admin_role)

    def __setattr__(self, attr_name, value):
        if not getattr(self, "_role_validation_disabled", False):
            self._validate_setattr(attr_name, value)

        return super().__setattr__(attr_name, value)

    def _validate_setattr(self, attr_name, value):
        if attr_name in self.set_attr_roles:
            require(
                self.has_role(self.set_attr_roles[attr_name], self._running_as),
                self._error(
                    "AccessControlUnauthorizedAccount", self._running_as, self.set_attr_roles[attr_name]
                ),
            )


def require(condition, message=None):
    if not condition:
        if isinstance(message, RevertError):
            raise message
        raise RevertError(message or "required condition not met")


class ERC20Token(AccessControlContract):
    ZERO = Wad(0)

    name = StringField()
    symbol = StringField(default="")
    decimals = IntField(default=18)
    balances = DictField(AddressField(), WadField(), default={})
    allowances = DictField(TupleField((AddressField(), AddressField())), WadField(), default={})

    _total_supply = WadField(default=ZERO)

    _arg_count_by_error = {
        "ERC20InsufficientBalance": 3,
        "ERC20InvalidSender": 1,
        "ERC20InvalidReceiver": 1,
        "ERC20InsufficientAllowance": 3,
        "ERC20InvalidApprover": 1,
        "ERC20InvalidSpender": 1,
    }

    _message_by_error = {
        "ERC20InsufficientBalance": "ERC20: transfer amount exceeds balance",
        "ERC20InvalidSender": "ERC20: transfer from the zero address",
        "ERC20InvalidReceiver": "ERC20: transfer to the zero address",
        "ERC20InsufficientAllowance": "ERC20: insufficient allowance",
        "ERC20InvalidApprover": "ERC20: approve from the zero address",
        "ERC20InvalidSpender": "ERC20: approve to the zero address",
    }

    def _error(self, error_class, *args) -> RevertError:
        if self.use_custom_errors:
            arg_count = self._arg_count_by_error.get(error_class, None)
            if arg_count == 1:
                return RevertCustomError(
                    error_class, args[0] if args else "0x0000000000000000000000000000000000000000"
                )
            elif arg_count is not None:
                return RevertCustomError(error_class, *args[:arg_count])
        else:
            message = self._message_by_error.get(error_class, None)
            if message is not None:
                return RevertError(message)
        return super()._error(error_class, *args)

    def __init__(self, **kwargs):
        if "initial_supply" in kwargs:
            initial_supply = kwargs.pop("initial_supply")
        else:
            initial_supply = None
        super().__init__(**kwargs)
        if initial_supply:
            self.mint(self.owner, initial_supply)

    def _parse_account(self, account):
        if isinstance(account, (Contract, ContractProxy)):
            return account.contract_id
        return account

    def _parse_accounts(self, *accounts):
        for account in accounts:
            if isinstance(account, (Contract, ContractProxy)):
                yield account.contract_id
            else:
                yield account

    def mint(self, address, amount):
        address = self._parse_account(address)
        self.balances[address] = self.balances.get(address, self.ZERO) + amount
        self._total_supply += amount

    def burn(self, address, amount):
        if amount == self.ZERO:
            return
        address = self._parse_account(address)
        balance = self.balances.get(address, self.ZERO)
        require(amount <= balance, "Not enought balance to burn")
        if amount == balance:
            del self.balances[address]
        else:
            self.balances[address] -= amount
        self._total_supply -= amount

    def balance_of(self, account):
        return self.balances.get(self._parse_account(account), self.ZERO)

    @external
    def transfer(self, sender, recipient, amount):
        return self._transfer(sender, recipient, amount)

    def _transfer(self, sender, recipient, amount):
        sender, recipient = self._parse_accounts(sender, recipient)
        if self.balance_of(sender) < amount:
            raise self._error("ERC20InsufficientBalance", sender, self.balance_of(sender), amount)
        elif self.balances[sender] == amount:
            del self.balances[sender]
        else:
            self.balances[sender] -= amount
        self.balances[recipient] = self.balances.get(recipient, self.ZERO) + amount
        return True

    @view
    def allowance(self, owner, spender):
        owner, spender = self._parse_accounts(owner, spender)
        return self.allowances.get((owner, spender), self.ZERO)

    def _approve(self, owner, spender, amount):
        owner, spender = self._parse_accounts(owner, spender)
        require(owner is not None, self._error("ERC20InvalidApprover"))
        require(spender is not None, self._error("ERC20InvalidSpender", spender))
        if amount == self.ZERO:
            try:
                del self.allowances[(owner, spender)]
            except KeyError:
                pass
        else:
            self.allowances[(owner, spender)] = amount

    @external
    def approve(self, sender, spender, amount):
        self._approve(sender, spender, amount)

    @external
    def increase_allowance(self, sender, spender, amount):
        self._approve(sender, spender, amount + self.allowances.get((sender, spender), self.ZERO))

    @external
    def decrease_allowance(self, sender, spender, amount):
        sender, spender = self._parse_accounts(sender, spender)
        allowance = self.allowances.get((sender, spender), self.ZERO)
        require(allowance >= amount, self._error("ERC20InsufficientAllowance", spender, allowance, amount))
        self._approve(sender, spender, allowance - amount)

    @external
    def transfer_from(self, spender, sender, recipient, amount):
        spender, sender, recipient = self._parse_accounts(spender, sender, recipient)
        allowance = self.allowances.get((sender, spender), self.ZERO)
        if allowance < amount:
            raise self._error("ERC20InsufficientAllowance", spender, allowance, amount)
        self._transfer(sender, recipient, amount)
        self._approve(sender, spender, allowance - amount)
        return True

    def total_supply(self):
        return self._total_supply


class ERC721Token(AccessControlContract):  # NFT
    ZERO = Wad(0)

    name = StringField()
    symbol = StringField(default="")
    owners = DictField(IntField(), AddressField(), default={})
    balances = DictField(AddressField(), IntField(), default={})
    token_approvals = DictField(IntField(), AddressField(), default={})
    # operator_approvals[A] = [OP1, OP2]
    operator_approvals = DictField(AddressField(), ListField(AddressField()), default={})

    _token_count = IntField(default=0)

    _arg_count_by_error = {
        "ERC721InvalidOwner": 1,
        "ERC721NonexistentToken": 1,
        "ERC721IncorrectOwner": 3,
        "ERC721InvalidSender": 1,
        "ERC721InvalidReceiver": 1,
        "ERC721InsufficientApproval": 2,
    }

    _message_by_error = {
        "ERC721InvalidOwner": "ERC721: address zero is not a valid owner",
        "ERC721NonexistentToken": "ERC721: invalid token ID",
        "ERC721IncorrectOwner": "ERC721: transfer from incorrect owner",
        "ERC721InvalidSender": "ERC721: transfer from incorrect owner",
        "ERC721InvalidReceiver": "ERC721: transfer to the zero address",
        "ERC721InsufficientApproval": "ERC721: caller is not token owner nor approved",
    }

    def _error(self, error_class, *args) -> RevertError:
        if self.use_custom_errors:
            arg_count = self._arg_count_by_error.get(error_class, None)
            if arg_count == 1:
                return RevertCustomError(
                    error_class, args[0] if args else "0x0000000000000000000000000000000000000000"
                )
            elif arg_count is not None:
                return RevertCustomError(error_class, *args[:arg_count])
        else:
            message = self._message_by_error.get(error_class, None)
            if message is not None:
                return RevertError(message)
        return super()._error(error_class, *args)

    @external
    def mint(self, to, token_id):
        if token_id is None:
            self._token_count += 1
            token_id = self._token_count
        if token_id in self.owners:
            if self.use_custom_errors:
                raise RevertError("ERC721: token already minted")
            else:
                raise self._error("ERC721InvalidSender")
        self.balances[to] = self.balances.get(to, 0) + 1
        self.owners[token_id] = to

    @external
    def burn(self, owner, token_id):
        if self.owners.get(token_id, None) != owner:
            raise RevertError("Not the owner")
        del self.owners[token_id]
        self.balances[owner] -= 1
        if token_id in self.token_approvals:
            del self.token_approvals[token_id]

    @view
    def balance_of(self, address):
        return self.balances.get(address, 0)

    @view
    def owner_of(self, token_id):
        if token_id not in self.owners:
            raise self._error("ERC721NonexistentToken", token_id)
        return self.owners[token_id]

    # def token_uri

    @external
    def approve(self, sender, spender, token_id):
        assert token_id in self.owners
        assert self.owners[token_id] == sender or sender in self.operator_approvals[self.owners[token_id]]
        self.token_approvals[token_id] = spender

    @view
    def get_approved(self, token_id):
        return self.token_approvals.get(token_id, None)

    @external
    def set_approval_for_all(self, sender, operator, approved):
        if approved:
            self.operator_approvals[sender] = self.operator_approvals.get(sender, []) + [operator]
        elif sender in self.operator_approvals and operator in self.operator_approvals[sender]:
            approvals = self.operator_approvals[sender]
            approvals.remove(operator)
            if not approvals:
                del self.operator_approvals[sender]
            else:
                self.operator_approvals[sender] = approvals

    def is_approved_for_all(self, owner, operator):
        return owner in self.operator_approvals and operator in self.operator_approvals[owner]

    @external
    def transfer_from(self, sender, from_, to, token_id):
        owner = self.owners[token_id]
        if (
            sender != owner
            and self.token_approvals.get(token_id, None) != sender
            and sender not in self.operator_approvals.get(owner, [])
        ):
            raise self._error("ERC721InsufficientApproval", sender, token_id)
        return self._transfer(from_, to, token_id)

    @external
    def safe_transfer_from(self, sender, from_, to, token_id):
        owner = self.owners[token_id]
        if (
            sender != owner
            and self.token_approvals.get(token_id, None) != sender
            and sender not in self.operator_approvals.get(owner, [])
        ):
            raise self._error("ERC721InsufficientApproval", sender, token_id)
        # TODO: if `to` is contract, call onERC721Received
        return self._transfer(from_, to, token_id)

    def _transfer(self, from_, to, token_id):
        if self.owners[token_id] != from_:
            raise self._error("ERC721InvalidOwner", from_)
        if token_id in self.token_approvals:
            del self.token_approvals[token_id]
        self.balances[from_] -= 1
        self.balances[to] = self.balances.get(to, 0) + 1
        self.owners[token_id] = to
