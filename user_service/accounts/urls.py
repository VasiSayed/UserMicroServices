from rest_framework.routers import DefaultRouter
from .views import UserViewSet, UserAccessViewSet, UserAccessRoleViewSet,UserAccessFullCreateView,UserAccessRoleDeleteView,UserAccessListByUserView,UserAccessListAPIView,ProjectCategoryUserAccessAPIView,UsersWithAccessesAndRolesByCreatorAPIView,UserDashboardAPIView
from django.urls import path

router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'accesses', UserAccessViewSet)
router.register(r'roles', UserAccessRoleViewSet)

urlpatterns = [
    path('user-access-full/', UserAccessFullCreateView.as_view()),
    path('user/<int:user_id>/role/<int:role_id>/delete/', UserAccessRoleDeleteView.as_view(), name='useraccessrole-delete'),
    path('user/<int:user_id>/accesses/', UserAccessListByUserView.as_view(), name='useraccess-list-by-user'),
    path('user-access-role/',UserAccessFullCreateView.as_view(),name='User_name_role'),
    path('user-access/', UserAccessListAPIView.as_view(), name='user-access-list'),
    path("project-category-user-access/", ProjectCategoryUserAccessAPIView.as_view()),
    path("users-by-creator/", UsersWithAccessesAndRolesByCreatorAPIView.as_view(), name="users-by-creator"),
    path('user-dashboard/', UserDashboardAPIView.as_view(), name='user-dashboard'),
]


urlpatterns += router.urls