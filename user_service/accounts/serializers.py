from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from .models import User, UserAccess, UserAccessRole

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id', 'username', 'first_name', 'last_name', 'email', 'phone_number',  # Added first_name and last_name
            'has_access', 'is_client', 'is_manager',
            'org', 'company', 'entity','password'
        ]
        extra_kwargs = {
            'password': {'write_only': True}  
        }
    def create(self, validated_data):
            password = validated_data.pop('password', None)
            user = User(**validated_data)
            print('hpassword checling')
            if password:
                print(f'gto pasword {password}')
                user.set_password(password)
            else:
                print('no password')
            user.save()
            return user

    def update(self, instance, validated_data):
            password = validated_data.pop('password', None)
            for attr, value in validated_data.items():
                setattr(instance, attr, value)
            if password:
                instance.set_password(password) 
            instance.save()
            return instance

class UserAccessRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAccessRole
        fields = [ 'role']

class UserAccessSerializer(serializers.ModelSerializer):
    roles = UserAccessRoleSerializer(many=True, read_only=True)
    class Meta:
        model = UserAccess
        fields = [
            'id',
            'user',
            'project_id',
            'building_id',
            'zone_id',
            'flat_id',
            'active',
            'created_at',
            'category',
            'CategoryLevel1',
            'CategoryLevel2',
            'CategoryLevel3',
            'CategoryLevel4',
            'CategoryLevel5',
            'CategoryLevel6',  
            'roles',
        ]




class UserAccessWithRolesCreateSerializer(serializers.ModelSerializer):
    roles = UserAccessRoleSerializer(many=True, write_only=True)
    user_id = serializers.IntegerField(write_only=True)

    class Meta:
        model = UserAccess
        fields = [
            'user_id',
            'project_id', 'building_id', 'zone_id', 'flat_id',
            'active', 'category', 'CategoryLevel1', 'roles'
        ]

    def validate_user_id(self, value):
        if not User.objects.filter(pk=value).exists():
            raise serializers.ValidationError("User with this id does not exist.")
        return value

    def create(self, validated_data):
        roles_data = validated_data.pop('roles')
        user_id = validated_data.pop('user_id')
        user = User.objects.get(pk=user_id)
        user_access = UserAccess.objects.create(user=user, **validated_data)
        roles = [UserAccessRole.objects.create(user_access=user_access, **role_data) for role_data in roles_data]
        return {
            "access": user_access,
            "roles": roles,
            "user": user
        }


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        print(f"DEBUG: Creating token for user {user.username}")
        token = super().get_token(user)
        token['user_id'] = user.id
        token['username'] = user.username
        token['email'] = user.email
        token['phone_number'] = user.phone_number
        token['has_access'] = user.has_access
        token['is_client'] = user.is_client
        token['is_manager'] = user.is_manager
        token['org'] = user.org
        token['company'] = user.company
        token['entity'] = user.entity
        token['superadmin'] = user.is_staff
        
        # Gather all roles and all access objects
        user_roles = []
        accesses_list = []  # ADD THIS LINE
        
        for access in user.accesses.all():
            print(f"DEBUG: Found access {access.id}")
            for role in access.roles.all():
                print(f"DEBUG: Found role {role.role}")
                user_roles.append(role.role)
            
            # ADD THIS BLOCK - Pack access info
            accesses_list.append({
                "project_id": access.project_id,
                "building_id": access.building_id,
                "zone_id": access.zone_id,
                "flat_id": access.flat_id,
                "category": access.category,
                "category_level1": access.CategoryLevel1,
                "category_level2": access.CategoryLevel2,
                "category_level3": access.CategoryLevel3,
                "category_level4": access.CategoryLevel4,
                "category_level5": access.CategoryLevel5,
                "category_level6": access.CategoryLevel6,
                "roles": [role.role for role in access.roles.all()],
                "active": access.active,
            })
        
        print(f"DEBUG: Final roles: {user_roles}")
        print(f"DEBUG: Final accesses: {accesses_list}")  # ADD THIS LINE
        
        token['roles'] = list(set(user_roles))
        token['accesses'] = accesses_list  # ADD THIS LINE
        print("DEBUG: Final accesses in token:", token.payload.get("accesses"))

  # <--- PRINT FULL TOKEN DATA

        return token

class UserWithAccessesSerializer(serializers.ModelSerializer):
    accesses = UserAccessSerializer(many=True, read_only=True)
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'phone_number', 'accesses']

    def validate(self, attrs):
        data = super().validate(attrs)
        
        # Get user roles
        user_roles = []
        for access in self.user.accesses.all():
            for role in access.roles.all():
                user_roles.append(role.role)
        
        data['user'] = {
            'user_id': self.user.id,
            'username': self.user.username,
            'first_name': self.user.first_name,
            'last_name': self.user.last_name,
            'email': self.user.email,
            'phone_number': self.user.phone_number,
            'date_joined': self.user.date_joined.strftime("%Y-%m-%d"),
            'last_login': self.user.last_login.strftime("%Y-%m-%d") if self.user.last_login else None,
            'has_access': self.user.has_access,
            'is_client': self.user.is_client,
            'is_manager': self.user.is_manager,
            'org': self.user.org,
            'company': self.user.company,
            'entity': self.user.entity,
            'superadmin': self.user.is_staff,
            'roles': list(set(user_roles))  # Add actual roles array
        }
        return data
    

class UserAccessCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating UserAccess without requiring user field"""
    class Meta:
        model = UserAccess
        fields = [
            'project_id',
            'building_id',
            'zone_id',
            'flat_id',
            'active',
            'category',
            'CategoryLevel1',
            'CategoryLevel2',
            'CategoryLevel3',
            'CategoryLevel4',
            'CategoryLevel5',
            'CategoryLevel6',
        ]

from django.db import transaction

class UserAccessFullSerializer(serializers.Serializer):
    user = UserSerializer()
    access = UserAccessCreateSerializer()  # Changed this line
    roles = UserAccessRoleSerializer(many=True)
    
    def create(self, validated_data):
        with transaction.atomic():
            user_data = validated_data.pop('user')
            access_data = validated_data.pop('access')
            roles_data = validated_data.pop('roles')
            
            # Create user first
            user_serializer = UserSerializer()
            user = user_serializer.create(user_data)
            
            # Create access directly (no need to pop 'user' since it's not in the serializer)
            user_access = UserAccess.objects.create(user=user, **access_data)
            
            role_objs = []
            for role in roles_data:
                role_obj = UserAccessRole.objects.create(user_access=user_access, **role)
                role_objs.append(role_obj)
                
            return {
                "user": user,
                "access": user_access,
                "roles": role_objs
            }